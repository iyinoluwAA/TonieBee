//! Every email the API sends. Like Claude's sign-in: the email holds a button, not
//! the code — so the code never shows in a phone's lock-screen preview. Tokens go
//! after `#`, which browsers never send to any server, so they stay out of hosting
//! logs and `Referer` headers.
//!
//! Visitor-typed text only ever enters the HTML through `mail::escape_html`.

use chrono::{DateTime, Utc};

use crate::{
    config::Config,
    mail::{button, escape_html, layout, Email},
};

pub const LINK_MINUTES: i64 = 10;

/// "Sign in" for a client.
pub fn sign_in(config: &Config, to: &str, link_token: &str) -> Email {
    let brand = &config.brand_name;
    let link = format!("{}/sign-in/link#{link_token}", config.site_url);
    let text = format!(
        "Sign in to {brand}\n\n\
         Open this link to sign in:\n{link}\n\n\
         It works for {LINK_MINUTES} minutes. If you open it on a different device, it shows a \
         6-digit code to type where you started.\n\n\
         {brand} will never ask you for your sign-in code by phone, text or email.\n\n\
         If you didn't ask to sign in, ignore this email. Nothing happens without the link."
    );
    let b = escape_html(brand);
    let body = format!(
        r#"<p style="margin:0 0 24px">Tap the button to sign in. It works for {LINK_MINUTES} minutes.</p>
<p style="margin:0 0 28px">{btn}</p>
<p style="margin:0 0 12px;color:#4a5568">Opened it on a different device? It will show a 6-digit code to type where you started.</p>
<p style="margin:0 0 12px;color:#4a5568"><strong>{b} will never ask you for your sign-in code</strong> by phone, text or email.</p>
<p style="margin:0;color:#4a5568">If you didn't ask to sign in, ignore this email. Nothing happens without the link.</p>"#,
        btn = button(&link, &format!("Sign in to {brand}")),
    );
    Email {
        to: to.to_string(),
        subject: format!("Sign in to {brand}"),
        text,
        html: layout(brand, &format!("Sign in to {b}"), &body),
    }
}

/// Sent instead of a sign-in link when an admin's address is typed into the client
/// sign-in: admins only sign in with password + authenticator.
pub fn admin_redirect(config: &Config, to: &str) -> Email {
    let brand = &config.brand_name;
    let admin = format!("{}/admin", config.site_url);
    let text = format!(
        "Someone asked to sign in to the {brand} website with this address.\n\n\
         This is an admin account, so it signs in at {admin} with your password and \
         authenticator app instead.\n\n\
         If this wasn't you, you can ignore this email."
    );
    let body = format!(
        r#"<p style="margin:0 0 16px">Someone asked to sign in to the website with this address.</p>
<p style="margin:0 0 16px">This is an admin account, so it signs in at <a href="{a}" style="color:#1e3a8a">{a}</a> with your password and authenticator app instead.</p>
<p style="margin:0;color:#4a5568">If this wasn't you, you can ignore this email.</p>"#,
        a = escape_html(&admin)
    );
    Email {
        to: to.to_string(),
        subject: format!("{brand} admin sign-in"),
        text,
        html: layout(brand, "Admin sign-in", &body),
    }
}

/// The one-time link that lets someone become an admin. Sent ONLY to the invited
/// address: whoever accepts has shown they can read that inbox.
pub fn admin_invite(
    config: &Config,
    to: &str,
    invited_by: &str,
    link_token: &str,
    hours: i32,
) -> Email {
    let brand = &config.brand_name;
    let link = format!("{}/admin/welcome#{link_token}", config.site_url);
    let text = format!(
        "{invited_by} invited you to help run the {brand} website.\n\n\
         Open this link to set up your admin sign-in (a password and an authenticator app on \
         your phone):\n{link}\n\n\
         It works once, for {hours} hours. If you weren't expecting this, ignore the email — \
         nothing happens without the link."
    );
    let body = format!(
        r#"<p style="margin:0 0 16px"><strong>{who}</strong> invited you to help run the {b} website.</p>
<p style="margin:0 0 24px">Set up your admin sign-in: you'll choose a password and add {b} to an authenticator app on your phone (Google Authenticator or Microsoft Authenticator).</p>
<p style="margin:0 0 28px">{btn}</p>
<p style="margin:0;color:#4a5568">The link works once, for {hours} hours. If you weren't expecting this, ignore the email — nothing happens without the link.</p>"#,
        who = escape_html(invited_by),
        b = escape_html(brand),
        btn = button(&link, "Set up my admin sign-in"),
    );
    Email {
        to: to.to_string(),
        subject: format!("You're invited to help run {brand}"),
        text,
        html: layout(brand, "You're invited", &body),
    }
}

/// An admin account signed in from a browser it had never used before.
pub fn new_device_alert(
    config: &Config,
    to: &str,
    device: &str,
    ip: &str,
    at: DateTime<Utc>,
) -> Email {
    let brand = &config.brand_name;
    let when = at.format("%Y-%m-%d %H:%M UTC");
    let account = format!("{}/admin/account", config.site_url);
    let text = format!(
        "Your {brand} admin account was signed in to from a new device.\n\n\
         Device: {device}\nNetwork address: {ip}\nWhen: {when}\n\n\
         If this was you, there's nothing to do.\n\
         If it wasn't: open {account}, choose \"Sign out everywhere\", then change your password. \
         Your authenticator code was needed too, so also check your phone is safe."
    );
    let body = format!(
        r#"<p style="margin:0 0 16px">Your admin account was signed in to from a <strong>new device</strong>.</p>
<p style="margin:0 0 16px;color:#4a5568">Device: {d}<br>Network address: {i}<br>When: {when}</p>
<p style="margin:0 0 16px">If this was you, there's nothing to do.</p>
<p style="margin:0">If it wasn't: open <a href="{a}" style="color:#1e3a8a">your account</a>, choose “Sign out everywhere”, then change your password.</p>"#,
        d = escape_html(device),
        i = escape_html(ip),
        a = escape_html(&account),
    );
    Email {
        to: to.to_string(),
        subject: format!("New sign-in to your {brand} admin account"),
        text,
        html: layout(brand, "New sign-in", &body),
    }
}

/// Too many wrong passwords or codes: sign-in is paused.
pub fn lockout_alert(config: &Config, to: &str, device_known: bool, minutes: i64) -> Email {
    let brand = &config.brand_name;
    let scope = if device_known {
        "one of your own devices"
    } else {
        "devices you haven't signed in from before"
    };
    let text = format!(
        "There were 5 wrong passwords or codes in a row for your {brand} admin account, from \
         {scope}. Signing in from there is paused for {minutes} minutes.\n\n\
         If this was you, wait and try again. If it wasn't, someone may be guessing: your \
         devices that signed in before still work, and the authenticator code still protects \
         the account. Consider changing your password from your account page."
    );
    let body = format!(
        r#"<p style="margin:0 0 16px">There were 5 wrong passwords or codes in a row for your admin account, from {scope}. Signing in from there is paused for {minutes} minutes.</p>
<p style="margin:0;color:#4a5568">If this was you, wait and try again. If it wasn't, someone may be guessing: your devices that signed in before still work, and your authenticator code still protects the account.</p>"#
    );
    Email {
        to: to.to_string(),
        subject: format!("{brand} admin sign-in paused"),
        text,
        html: layout(brand, "Sign-in paused", &body),
    }
}

/// A new consultation request for the owner. Deliberately thin: no phone number,
/// email address or message in the email itself — those stay behind the admin
/// sign-in (an email inbox is the most common thing to be broken into).
pub fn new_request_notice(
    config: &Config,
    to: &str,
    first_name: &str,
    summary: &str,
    request_id: uuid::Uuid,
) -> Email {
    let brand = &config.brand_name;
    let link = format!("{}/admin/requests/{request_id}", config.site_url);
    let text = format!(
        "New consultation request from {first_name} — {summary}.\n\n\
         Open it (you'll sign in first): {link}"
    );
    let body = format!(
        r#"<p style="margin:0 0 16px">New consultation request from <strong>{n}</strong> — {s}.</p>
<p style="margin:0 0 16px;color:#4a5568">Their contact details are in the dashboard, behind your sign-in.</p>
<p style="margin:0">{btn}</p>"#,
        n = escape_html(first_name),
        s = escape_html(summary),
        btn = button(&link, "Open the request"),
    );
    Email {
        to: to.to_string(),
        subject: format!("New consultation request — {first_name}"),
        text,
        html: layout(brand, "New consultation request", &body),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_names_never_become_html_in_emails() {
        let c = Config::test_defaults();
        let evil = r#"<a href="https://evil.example">Verify your account</a>"#;
        let mail = new_request_notice(
            &c,
            "owner@example.com",
            evil,
            "life insurance, ON",
            uuid::Uuid::nil(),
        );
        assert!(
            !mail.html.contains("<a href=\"https://evil"),
            "{}",
            mail.html
        );
        assert!(mail.html.contains("&lt;a href="));
        let invite = admin_invite(&c, "new@example.com", evil, &"a".repeat(64), 24);
        assert!(!invite.html.contains("<a href=\"https://evil"));
    }

    #[test]
    fn sign_in_email_has_the_link_but_never_a_code() {
        let c = Config::test_defaults();
        let token = "b".repeat(64);
        let mail = sign_in(&c, "client@example.com", &token);
        assert!(mail.text.contains(&format!("/sign-in/link#{token}")));
        assert!(!mail.text.chars().collect::<String>().contains("code:"));
    }

    #[test]
    fn request_notice_keeps_contact_details_out_of_the_inbox() {
        let c = Config::test_defaults();
        let mail = new_request_notice(
            &c,
            "owner@example.com",
            "Ada",
            "life insurance, ON",
            uuid::Uuid::nil(),
        );
        assert!(mail.text.contains("Ada") && mail.text.contains("/admin/requests/"));
    }
}
