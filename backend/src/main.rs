use std::net::SocketAddr;

use tracing_subscriber::EnvFilter;

use toniebee_api::{
    cleanup, cli, config::Config, db, mail::Mailer, modules::accounts::password, router,
    state::AppState,
};

#[tokio::main]
async fn main() {
    // `toniebee-api <command>` runs a command-line task instead of the server.
    let mut args = std::env::args().skip(1);
    if let Some(command) = args.next() {
        let rest: Vec<String> = args.collect();
        cli::run(&command, &rest).await;
        return;
    }

    let config = Config::from_env();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("toniebee_api=info,tower_http=info")),
        )
        .init();

    let db = db::connect(&config).await;
    tokio::task::spawn_blocking(password::warm_up);
    cleanup::spawn(db.clone());
    let mailer = Mailer::from_config(&config);
    if matches!(mailer, Mailer::Disabled) {
        tracing::warn!("no email provider configured: sign-in emails are switched off");
    }

    let addr = config.socket_addr();
    tracing::info!(%addr, env = %config.app_env, "TonieBee API listening");

    let state = AppState::new(config, db, mailer);
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("could not bind address");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .expect("server error");
}

/// Ctrl+C on the laptop, SIGTERM from the host (Render sends it before a redeploy):
/// finish the requests in flight, then stop.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.ok();
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            signal.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
