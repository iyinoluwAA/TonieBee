use axum::{
    extract::Request,
    middleware::Next,
    response::Response,
};

/// IP address stored in request extensions
#[derive(Clone, Debug)]
pub struct ClientIp(pub String);

/// Middleware to extract IP and add to request extensions
pub async fn ip_extractor_middleware(
    mut req: Request,
    next: Next,
) -> Response {
    let ip = extract_ip_from_headers(req.headers());
    
    // Add IP to request extensions
    req.extensions_mut().insert(ClientIp(ip));
    
    next.run(req).await
}

fn extract_ip_from_headers(headers: &axum::http::HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|h| h.to_str().ok())
        .map(|s| {
            s.split(',')
                .next()
                .unwrap_or(s)
                .trim()
                .to_string()
        })
        .unwrap_or_else(|| "unknown".to_string())
}

