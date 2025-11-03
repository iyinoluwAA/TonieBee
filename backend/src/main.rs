mod config;
mod db;
mod dtos;
mod error;
mod handler;
mod mail;
mod middleware;
mod models;
mod routes;
mod utils;
mod middle_ware;


use std::{sync::Arc, time::Instant};

use axum::http::{
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE},
    HeaderValue, Method,
};
use config::Config;
use db::DBClient;
use dotenv::dotenv;
use routes::create_router;
use sqlx::postgres::PgPoolOptions;
use tower_http::cors::CorsLayer;
use tracing_subscriber::filter::LevelFilter;

#[derive(Debug, Clone)]
pub struct AppState {
    pub env: Config,
    pub db_client: DBClient,
    pub start_time: Instant,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(LevelFilter::DEBUG)
        .init();

    dotenv().ok();

    let config = Config::init();

    let pool = match PgPoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await
    {
        Ok(pool) => {
            println!("✅Connection to the database is successful!");
            pool
        }
        Err(err) => {
            println!("🔥 Failed to connect to the database: {:?}", err);
            std::process::exit(1);
        }
    };

    // Allow both common frontend dev ports (Vite default is 5173, but some setups use 3000)
    let allowed_origins = vec![
        "http://localhost:5173".parse::<HeaderValue>().unwrap(), // Vite default
        "http://localhost:3000".parse::<HeaderValue>().unwrap(), // Alternative
    ];
    let cors = CorsLayer::new()
        .allow_origins(allowed_origins)
        .allow_headers([AUTHORIZATION, ACCEPT, CONTENT_TYPE])
        .allow_credentials(true)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE]);

    let db_client = DBClient::new(pool);
    let app_state = AppState {
        env: config.clone(),
        db_client,
        start_time: Instant::now(),
    };

    let app = create_router(Arc::new(app_state.clone())).layer(cors.clone());

    println!(
        "🚀 Server is running on http://localhost:{}", config.port
    );

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", &config.port))
        .await
        .unwrap();

    axum::serve(listener, app).await.unwrap();
}
