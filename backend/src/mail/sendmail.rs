use lettre::{
    message::{header, SinglePart},
    transport::smtp::authentication::Credentials,
    Message, SmtpTransport, Transport,
};
use std::{env, fs};

pub async fn send_email(
    to_email: &str,
    subject: &str,
    template_path: &str,
    placeholders: &[(String, String)],
) -> Result<(), Box<dyn std::error::Error>> {
    // In development, use MailHog (no auth, no TLS)
    // In production, use authenticated SMTP with TLS
    let is_dev = std::env::var("RUST_ENV").unwrap_or_default() != "production";
    
    // Get SMTP settings with defaults for MailHog
    let smtp_server = if is_dev {
        env::var("SMTP_SERVER").unwrap_or_else(|_| "127.0.0.1".to_string())
    } else {
        env::var("SMTP_SERVER")?
    };
    
    let smtp_port: u16 = if is_dev {
        env::var("SMTP_PORT")
            .unwrap_or_else(|_| "1025".to_string())
            .parse()
            .unwrap_or(1025)
    } else {
        env::var("SMTP_PORT")?.parse()?
    };
    
    let is_mailhog = smtp_server == "127.0.0.1" || smtp_server == "localhost";
    
    // Only require username/password for real SMTP (not MailHog)
    let smtp_username = if is_dev && is_mailhog {
        env::var("SMTP_USERNAME").unwrap_or_else(|_| "dev@localhost".to_string())
    } else {
        env::var("SMTP_USERNAME")?
    };
    
    let smtp_password = if is_dev && is_mailhog {
        env::var("SMTP_PASSWORD").unwrap_or_else(|_| "".to_string())
    } else {
        env::var("SMTP_PASSWORD")?
    };

    let mut html_template = fs::read_to_string(template_path)?;

    for (key, value) in placeholders {
        html_template = html_template.replace(key, value)
    }

    let email = Message::builder()
        .from(smtp_username.parse()?)
        .to(to_email.parse()?)
        .subject(subject)
        .header(header::ContentType::TEXT_HTML)
        .singlepart(
            SinglePart::builder()
                .header(header::ContentType::TEXT_HTML)
                .body(html_template),
        )?;
    
    let mailer = if is_dev && is_mailhog {
        // MailHog: no authentication, no TLS
        SmtpTransport::builder_dangerous(smtp_server)
            .port(smtp_port)
            .build()
    } else {
        // Production SMTP: use authentication and TLS
        let creds = Credentials::new(smtp_username.clone(), smtp_password.clone());
        SmtpTransport::starttls_relay(&smtp_server)?
            .credentials(creds)
            .port(smtp_port)
            .build()
    };

    let result = mailer.send(&email);

    match result {
        Ok(_) => println!("Email sent successfully!"),
        Err(e) => println!("Failed to send email: {:?}", e),
    }

    Ok(())
}
