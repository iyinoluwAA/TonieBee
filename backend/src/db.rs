use std::time::Duration;

use sqlx::{postgres::PgPoolOptions, PgPool};

use crate::{config::Config, MIGRATOR};

/// Connects and brings the schema up to date (migrations are embedded in the binary).
pub async fn connect(config: &Config) -> PgPool {
    let db = PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&config.database_url)
        .await
        .expect("could not connect to the database (is it running? see backend/README.md)");
    MIGRATOR.run(&db).await.expect("database migrations failed");
    db
}
