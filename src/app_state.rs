use sqlx::{postgres::PgPoolOptions, Postgres,Pool};
use crate::app_config::AppConfig;
pub struct AppState {
    pub config: AppConfig,
    pub db: Pool<Postgres>,
}