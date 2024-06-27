use axum::{
    routing::{delete, get, patch, post}, Extension, Router,
};
use crate::server::handlers;
use crate::app_state::AppState;
use std::sync::Mutex;
use std::sync::Arc;

pub fn define_route(app_state: &Arc<Mutex<AppState>>) -> Router{
    let app = Router::new().route("/api/v1/signup", post(handlers::signup::signup_handler)).layer(Extension(Arc::clone(app_state))).
    route("/api/v1/activate-user/token/:token", get(handlers::activate_user::activate_user_handler)).layer(Extension(Arc::clone(app_state)))
    .route("/api/v1/login", post(handlers::login::login_handler)).layer(Extension(Arc::clone(app_state)))
    .route("/", get(|| async { println!("home endpoint hit");"Welcome Home!" }))
    ;
    app.with_state(app_state.to_owned())
}