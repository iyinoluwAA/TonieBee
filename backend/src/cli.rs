//! Command-line tasks: `toniebee-api <command>` (run from `backend/`).
//!
//! `create-admin <email>` makes the first admin (after that, admins invite each other
//! from the dashboard). It runs on a computer with the database's address, never over
//! the web. `check-email [to]` tests the email settings.

use std::io::{self, BufRead, Write};

use qrcode::{render::unicode::Dense1x2, QrCode};

use crate::{
    config::Config,
    db,
    mail::{Email, Mailer},
    modules::accounts::{admin, normalize_email, password, totp},
};

pub async fn run(command: &str, args: &[String]) {
    match command {
        "create-admin" => create_admin(args).await,
        "check-email" => check_email(args).await,
        "help" | "--help" | "-h" => print_help(),
        other => {
            eprintln!("Unknown command '{other}'.\n");
            print_help();
            std::process::exit(2);
        }
    }
}

fn print_help() {
    println!(
        "toniebee-api                      start the API server\n\
         toniebee-api create-admin <email> make <email> an admin, or reset an admin's\n\
         \x20                                 password, authenticator and backup codes\n\
         toniebee-api check-email [to]     test the email settings; with an address, send\n\
         \x20                                 a test email to it"
    );
}

async fn check_email(args: &[String]) {
    let config = Config::from_env();
    let Mailer::Smtp(smtp) = Mailer::from_config(&config) else {
        fail("MAIL_PROVIDER isn't smtp, so there's no email service to check.");
    };
    let host = config.smtp.host.clone().unwrap_or_default();
    match smtp.check().await {
        Ok(()) => println!(
            "✓ Connected to {host}:{} ({}).",
            config.smtp.port, config.smtp.tls
        ),
        Err(err) => fail(&format!(
            "Couldn't connect to {host}:{} — {err}",
            config.smtp.port
        )),
    }
    let Some(to) = args.first() else { return };
    let Some(to) = normalize_email(to) else {
        fail("That isn't an email address.");
    };
    let brand = &config.brand_name;
    let email = Email {
        to: to.clone(),
        subject: format!("{brand} email test"),
        text: format!("If you can read this, {brand}'s email works."),
        html: format!(
            "<p>If you can read this, {}'s email works.</p>",
            crate::mail::escape_html(brand)
        ),
    };
    match Mailer::Smtp(smtp).send(email).await {
        Ok(()) => println!("✓ Sent a test email to {to} — check its inbox (and spam folder)."),
        Err(err) => fail(&format!("Connected, but the test email wasn't sent: {err}")),
    }
}

async fn create_admin(args: &[String]) {
    let Some(email) = args.first().and_then(|raw| normalize_email(raw)) else {
        fail("Usage: toniebee-api create-admin <email>");
    };
    let config = Config::from_env();
    let db = db::connect(&config).await;

    let existing: Option<String> = sqlx::query_scalar("SELECT role FROM users WHERE email = $1")
        .bind(&email)
        .fetch_optional(&db)
        .await
        .unwrap_or_else(|e| fail(&format!("database error: {e}")));
    match existing.as_deref() {
        Some("admin") => {
            println!("{email} is already an admin. This RESETS their password, authenticator");
            println!("and backup codes, and signs them out everywhere.");
            confirm("Type RESET to continue: ", "RESET");
        }
        Some(_) => {
            println!("{email} has a client account. It will become an admin account.");
            confirm("Type ADMIN to continue: ", "ADMIN");
        }
        None => println!("Creating admin {email}."),
    }

    // 1. Password.
    let password = loop {
        let first = rpassword::prompt_password(format!(
            "\nNew password ({}+ characters; typing is hidden): ",
            password::MIN_LENGTH
        ))
        .unwrap_or_else(|_| fail("couldn't read the password"));
        if let Err(problem) = password::check_strength(&first, &email, &config.brand_name) {
            println!("  ✗ {problem}");
            continue;
        }
        let again = rpassword::prompt_password("Type it again: ")
            .unwrap_or_else(|_| fail("couldn't read the password"));
        if again != first {
            println!("  ✗ They don't match. Try again.");
            continue;
        }
        break first;
    };

    // 2. Authenticator app.
    let secret = totp::new_secret();
    let url = totp::otpauth_url(&secret, &config.brand_name, &email);
    let qr = QrCode::new(url.as_bytes())
        .unwrap_or_else(|_| fail("couldn't draw the QR code"))
        .render::<Dense1x2>()
        .dark_color(Dense1x2::Light)
        .light_color(Dense1x2::Dark)
        .quiet_zone(true)
        .build();
    println!("\nScan this with an authenticator app (Google Authenticator, Microsoft");
    println!("Authenticator, Authy or 1Password):\n\n{qr}\n");
    println!(
        "Can't scan? Add it by hand — key: {}",
        totp::grouped(&totp::secret_base32(&secret))
    );

    let mut confirmed_step = None;
    for _ in 0..3 {
        let code = prompt("\nType the 6-digit code the app shows now: ");
        let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
        match totp::matching_step(&secret, &code, totp::now_secs()) {
            Some(step) => {
                confirmed_step = Some(step);
                break;
            }
            None => println!("  ✗ That code doesn't match. Check the phone's clock is automatic."),
        }
    }
    let Some(confirmed_step) = confirmed_step else {
        fail("No working code after 3 tries — nothing was saved. Run the command again.");
    };

    // 3. Save.
    let enrolment = admin::enrol(&db, &config, &email, password, &secret, confirmed_step)
        .await
        .unwrap_or_else(|e| fail(&format!("couldn't save: {e}")));

    println!(
        "\n✓ {email} is {}.",
        if enrolment.replaced_existing {
            "set up with a new password and authenticator"
        } else {
            "now an admin"
        }
    );
    println!("\nBackup codes — each works ONCE if the phone is lost. Write them down or");
    println!("keep them in a password manager. They will not be shown again:\n");
    for pair in enrolment.backup_codes.chunks(2) {
        let line: Vec<String> = pair.iter().map(|c| admin::display_backup_code(c)).collect();
        println!("    {}", line.join("      "));
    }
    println!(
        "\nSign in at the website's /admin with this email, the password, and the app's code."
    );
}

fn prompt(label: &str) -> String {
    print!("{label}");
    io::stdout().flush().ok();
    let mut line = String::new();
    io::stdin()
        .lock()
        .read_line(&mut line)
        .unwrap_or_else(|_| fail("couldn't read input"));
    line.trim().to_string()
}

fn confirm(label: &str, word: &str) {
    if prompt(label) != word {
        fail("Cancelled — nothing changed.");
    }
}

fn fail(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(1);
}
