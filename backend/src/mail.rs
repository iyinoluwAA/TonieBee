//! Outgoing email.
//! - `MAIL_PROVIDER=smtp`: a real email service over SMTP (e.g. Brevo's free plan);
//! - development: emails are printed to the server log (`MAIL_PROVIDER=log`);
//! - production without a provider: sending fails with a clear message, so sign-in
//!   links can never end up in a production log;
//! - tests: emails are kept in memory so tests can read the links.
//!
//! Anything a visitor typed (a name, an email address) goes into an email's HTML only
//! through [`escape_html`] — the old TonieBee templates pasted names in raw, so a
//! "name" could add a link to an email sent in the business's name.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use lettre::{
    message::{Mailbox, MultiPart},
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};

use crate::{
    config::{Config, SmtpConfig},
    error::{AppError, AppResult},
};

#[derive(Debug, Clone)]
pub struct Email {
    pub to: String,
    pub subject: String,
    pub text: String,
    pub html: String,
}

#[derive(Clone)]
pub enum Mailer {
    Smtp(Arc<Smtp>),
    Log,
    Memory(Arc<Mutex<Vec<Email>>>),
    Disabled,
}

pub struct Smtp {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
    reply_to: Option<Mailbox>,
}

impl Mailer {
    pub fn from_config(config: &Config) -> Self {
        match config.mail_provider.as_deref() {
            Some("smtp") => Mailer::Smtp(Arc::new(Smtp::from_config(
                &config.smtp,
                config.is_production(),
            ))),
            Some("log") if config.is_production() => panic!(
                "MAIL_PROVIDER=log prints sign-in links to the server log — not allowed in production"
            ),
            Some("log") => Mailer::Log,
            None if !config.is_production() => Mailer::Log,
            None => Mailer::Disabled,
            Some(other) => panic!("unknown MAIL_PROVIDER '{other}' (supported: smtp, log)"),
        }
    }

    pub fn memory() -> Self {
        Mailer::Memory(Arc::new(Mutex::new(Vec::new())))
    }

    /// Emails sent so far (memory mailer only).
    pub fn sent(&self) -> Vec<Email> {
        match self {
            Mailer::Memory(sent) => sent.lock().expect("mailer mutex").clone(),
            _ => Vec::new(),
        }
    }

    pub async fn send(&self, email: Email) -> AppResult<()> {
        match self {
            Mailer::Smtp(smtp) => smtp.send(email).await,
            Mailer::Log => {
                // tools/dev_inbox.py reads these lines: keep the To:/Subject: format.
                tracing::info!(
                    "DEV EMAIL (not sent — no email provider yet)\nTo: {}\nSubject: {}\n\n{}\nEND DEV EMAIL",
                    email.to,
                    email.subject,
                    email.text
                );
                Ok(())
            }
            Mailer::Memory(sent) => {
                sent.lock().expect("mailer mutex").push(email);
                Ok(())
            }
            Mailer::Disabled => Err(AppError::ServiceUnavailable(
                "Email isn't switched on yet, so this is unavailable. Please try again later."
                    .into(),
            )),
        }
    }

    /// For notices whose failure shouldn't undo what the visitor just did (a new
    /// request saved, a sign-in finished): logged, never shown to them.
    pub async fn send_notice(&self, email: Email) {
        let kind = email.subject.clone();
        if let Err(err) = self.send(email).await {
            tracing::warn!(error = %err, %kind, "notice email not sent");
        }
    }
}

impl Smtp {
    /// Panics on settings that can't work, so a mistake stops the server at start-up
    /// instead of surfacing later as "the sign-in email never came".
    pub fn from_config(c: &SmtpConfig, production: bool) -> Self {
        let host = c
            .host
            .as_deref()
            .expect("MAIL_PROVIDER=smtp needs SMTP_HOST");
        let from_address = c
            .from
            .as_deref()
            .expect("MAIL_PROVIDER=smtp needs MAIL_FROM");
        let from = Mailbox::new(
            Some(c.from_name.clone()),
            from_address
                .parse()
                .unwrap_or_else(|_| panic!("MAIL_FROM isn't an email address: {from_address}")),
        );
        let reply_to = c.reply_to.as_deref().map(|address| {
            Mailbox::new(
                Some(c.from_name.clone()),
                address
                    .parse()
                    .unwrap_or_else(|_| panic!("MAIL_REPLY_TO isn't an email address: {address}")),
            )
        });

        let builder = match c.tls.as_str() {
            "tls" => AsyncSmtpTransport::<Tokio1Executor>::relay(host).expect("SMTP_HOST"),
            "starttls" => {
                AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host).expect("SMTP_HOST")
            }
            "none" if production => {
                panic!("SMTP_TLS=none sends sign-in links unencrypted — not allowed in production")
            }
            "none" => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host),
            other => panic!("SMTP_TLS must be tls, starttls or none (got {other})"),
        };
        let builder = builder.port(c.port).timeout(Some(Duration::from_secs(15)));
        let builder = match (&c.username, &c.password) {
            (Some(user), Some(password)) => builder.credentials(Credentials::new(
                user.clone(),
                String::from_utf8(password.expose().to_vec()).expect("SMTP_PASSWORD is text"),
            )),
            (None, None) if !production => builder,
            _ => panic!("SMTP_USERNAME and SMTP_PASSWORD must both be set"),
        };
        Self {
            transport: builder.build(),
            from,
            reply_to,
        }
    }

    pub fn message(&self, email: Email) -> AppResult<Message> {
        let to: Mailbox = email
            .to
            .parse()
            .map_err(|_| AppError::BadRequest("That email address can't receive mail.".into()))?;
        let mut builder = Message::builder()
            .from(self.from.clone())
            .to(to)
            .subject(email.subject);
        if let Some(reply_to) = &self.reply_to {
            builder = builder.reply_to(reply_to.clone());
        }
        builder
            .multipart(MultiPart::alternative_plain_html(email.text, email.html))
            .map_err(|_| AppError::Internal)
    }

    async fn send(&self, email: Email) -> AppResult<()> {
        let domain = email.to.rsplit('@').next().unwrap_or("?").to_string();
        let message = self.message(email)?;
        match self.transport.send(message).await {
            Ok(_) => Ok(()),
            Err(err) => {
                // Never log the message itself: it may carry a sign-in link.
                tracing::error!(error = %err, to_domain = %domain, "email not sent");
                Err(AppError::ServiceUnavailable(
                    "We couldn't send the email just now. Please try again in a few minutes."
                        .into(),
                ))
            }
        }
    }

    /// Connects and greets the server (and starts encryption), without sending anything.
    pub async fn check(&self) -> Result<(), String> {
        match self.transport.test_connection().await {
            Ok(true) => Ok(()),
            Ok(false) => Err("the server didn't answer as expected".into()),
            Err(err) => Err(err.to_string()),
        }
    }
}

/// Makes typed-in text safe inside an email's HTML (and attribute values).
pub fn escape_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// The shared look of every email: a white card on a soft background, the brand on
/// top. `heading` and `body_html` must already be safe HTML.
pub fn layout(brand: &str, heading: &str, body_html: &str) -> String {
    let brand = escape_html(brand);
    format!(
        r#"<!doctype html>
<html lang="en"><body style="margin:0;background:#f3f5f9;font-family:Helvetica,Arial,sans-serif;color:#14213d">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="padding:32px 16px">
<tr><td align="center">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:500px;background:#ffffff;border-radius:14px;padding:36px 32px">
<tr><td style="font-size:15px;font-weight:700;letter-spacing:.02em;color:#1e3a8a;padding-bottom:24px">{brand}</td></tr>
<tr><td style="font-size:22px;font-weight:700;padding-bottom:16px">{heading}</td></tr>
<tr><td style="font-size:15px;line-height:1.6">{body_html}</td></tr>
</table>
</td></tr>
</table>
</body></html>"#
    )
}

/// A button-style link for emails. `href` must be one we built (not typed by a visitor).
pub fn button(href: &str, label: &str) -> String {
    format!(
        r#"<a href="{href}" style="display:inline-block;background:#1e3a8a;color:#ffffff;text-decoration:none;font-weight:600;padding:13px 26px;border-radius:999px">{label}</a>"#,
        href = escape_html(href),
        label = escape_html(label)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn smtp(reply_to: Option<&str>) -> Smtp {
        Smtp::from_config(
            &SmtpConfig {
                host: Some("localhost".into()),
                port: 1025,
                tls: "none".into(),
                from: Some("hello@example.com".into()),
                from_name: "Toniebee".into(),
                reply_to: reply_to.map(Into::into),
                ..Default::default()
            },
            false,
        )
    }

    fn sample() -> Email {
        Email {
            to: "client@example.com".into(),
            subject: "Sign in to Toniebee".into(),
            text: "Open this link to sign in".into(),
            html: "<p>Tap the button</p>".into(),
        }
    }

    #[test]
    fn emails_say_who_they_are_from_and_where_replies_go() {
        let raw = String::from_utf8(
            smtp(Some("hello@example.com"))
                .message(sample())
                .unwrap()
                .formatted(),
        )
        .unwrap();
        assert!(raw.contains("From: Toniebee <hello@example.com>"), "{raw}");
        assert!(raw.contains("Reply-To: Toniebee <hello@example.com>"));
        assert!(raw.contains("To: client@example.com"));
        assert!(raw.contains("multipart/alternative"));
    }

    #[test]
    fn reply_to_is_optional() {
        let raw = String::from_utf8(smtp(None).message(sample()).unwrap().formatted()).unwrap();
        assert!(!raw.contains("Reply-To"));
    }

    #[test]
    fn typed_text_cannot_become_html() {
        assert_eq!(
            escape_html(r#"<a href="https://evil">Verify</a> & 'x'"#),
            "&lt;a href=&quot;https://evil&quot;&gt;Verify&lt;/a&gt; &amp; &#39;x&#39;"
        );
        let html = layout("<b>Brand</b>", "Hi", "<p>ok</p>");
        assert!(html.contains("&lt;b&gt;Brand&lt;/b&gt;") && !html.contains("<b>Brand"));
    }

    #[test]
    #[should_panic(expected = "not allowed in production")]
    fn unencrypted_email_is_refused_in_production() {
        Smtp::from_config(
            &SmtpConfig {
                host: Some("smtp.example.com".into()),
                port: 25,
                tls: "none".into(),
                from: Some("a@example.com".into()),
                from_name: "Toniebee".into(),
                ..Default::default()
            },
            true,
        );
    }

    #[test]
    #[should_panic(expected = "must both be set")]
    fn production_needs_a_login_for_the_email_service() {
        Smtp::from_config(
            &SmtpConfig {
                host: Some("smtp-relay.brevo.com".into()),
                port: 587,
                tls: "starttls".into(),
                from: Some("a@example.com".into()),
                from_name: "Toniebee".into(),
                ..Default::default()
            },
            true,
        );
    }
}
