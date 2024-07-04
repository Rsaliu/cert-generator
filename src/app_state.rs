use sqlx::{postgres::PgPoolOptions, Postgres,Pool};
use crate::messenger::messenger::{Message,Messenger};
use crate::app_config::AppConfig;
use std::sync::{Arc,Mutex};
use tokio::sync::mpsc::{Sender, Receiver};
pub struct AppState {
    pub config: AppConfig,
    pub db: Pool<Postgres>,
    pub messenger_channel_sender: Sender<Message>
}