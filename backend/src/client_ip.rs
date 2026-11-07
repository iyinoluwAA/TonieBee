//! The visitor's IP address, for rate limits and the audit log.
//!
//! rust-auth-kit trusted the first `X-Forwarded-For` entry, which any client
//! can write itself — so its limits could be dodged by sending a fake header.
//! Here the header is only read when the API sits behind known proxies, and
//! then from the right: each trusted proxy appends the address it saw, so the
//! entry `TRUSTED_PROXY_HOPS` from the end is the real visitor.

use std::{
    net::{IpAddr, SocketAddr},
    sync::atomic::{AtomicBool, Ordering},
};

use axum::{
    async_trait,
    extract::{ConnectInfo, FromRequestParts},
    http::request::Parts,
};

use crate::{error::AppError, state::AppState};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientIp(pub String);

#[async_trait]
impl FromRequestParts<AppState> for ClientIp {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, AppError> {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| addr.ip());
        let forwarded = parts
            .headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok());
        if forwarded.is_some() && state.config.trusted_proxy_hops == 0 {
            warn_once_about_proxies();
        }
        Ok(ClientIp(resolve(
            peer,
            forwarded,
            state.config.trusted_proxy_hops,
        )))
    }
}

/// A proxy is adding `X-Forwarded-For` but `TRUSTED_PROXY_HOPS` is 0: every visitor
/// then looks like the proxy, so per-visitor limits would act on everyone at once.
fn warn_once_about_proxies() {
    static WARNED: AtomicBool = AtomicBool::new(false);
    if !WARNED.swap(true, Ordering::Relaxed) {
        tracing::warn!(
            "requests carry X-Forwarded-For but TRUSTED_PROXY_HOPS=0 — if a proxy sits in front \
             of the API, set TRUSTED_PROXY_HOPS (backend/README.md → Client IP)"
        );
    }
}

/// The key rate limits count by. An IPv6 user typically controls a whole /64
/// (billions of addresses), so limits apply to the /64, not one address.
pub fn rate_key(ip: &str) -> String {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            }
        },
        _ => ip.to_string(),
    }
}

pub fn resolve(peer: Option<IpAddr>, forwarded_for: Option<&str>, trusted_hops: usize) -> String {
    let peer_text = || peer.map_or_else(|| "unknown".to_string(), |ip| ip.to_string());
    if trusted_hops == 0 {
        return peer_text();
    }
    let entries: Vec<&str> = forwarded_for
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .collect();
    if entries.len() < trusted_hops {
        return peer_text();
    }
    entries[entries.len() - trusted_hops]
        .parse::<IpAddr>()
        .map(|ip| ip.to_string())
        .unwrap_or_else(|_| peer_text())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> Option<IpAddr> {
        Some("10.0.0.1".parse().unwrap())
    }

    #[test]
    fn without_proxies_the_header_is_ignored() {
        assert_eq!(resolve(peer(), Some("1.2.3.4"), 0), "10.0.0.1");
        assert_eq!(resolve(None, None, 0), "unknown");
    }

    #[test]
    fn behind_proxies_a_forged_first_entry_is_ignored() {
        // Visitor forged "6.6.6.6"; the one trusted proxy appended the real 41.58.0.9.
        assert_eq!(resolve(peer(), Some("6.6.6.6, 41.58.0.9"), 1), "41.58.0.9");
        // Two proxies (e.g. Vercel → Render): the real visitor is second from the end.
        assert_eq!(
            resolve(peer(), Some("6.6.6.6, 41.58.0.9, 76.76.21.1"), 2),
            "41.58.0.9"
        );
    }

    #[test]
    fn ipv6_visitors_are_limited_per_network_not_per_address() {
        assert_eq!(rate_key("2001:db8:aa:bb:1:2:3:4"), "2001:db8:aa:bb::/64");
        assert_eq!(
            rate_key("2001:db8:aa:bb:ffff:ffff:ffff:ffff"),
            "2001:db8:aa:bb::/64"
        );
        assert_eq!(rate_key("::ffff:41.58.0.9"), "41.58.0.9");
        assert_eq!(rate_key("41.58.0.9"), "41.58.0.9");
        assert_eq!(rate_key("unknown"), "unknown");
    }

    #[test]
    fn missing_or_garbage_header_falls_back_to_the_connection() {
        assert_eq!(resolve(peer(), None, 1), "10.0.0.1");
        assert_eq!(resolve(peer(), Some("not-an-ip"), 1), "10.0.0.1");
    }
}
