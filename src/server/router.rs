use axum::{
    routing::{delete, get, patch, post}, Extension, Router,
    middleware::{self}
};
use crate::server::handlers;
use crate::app_state::AppState;
use std::sync::Mutex;
use std::sync::Arc;
use crate::server::auth::jwt_auth;

pub fn define_route(app_state: &Arc<Mutex<AppState>>) -> Router{
    let app = Router::new().route("/api/v1/signup", post(handlers::signup::signup_handler)).
    route("/api/v1/activate-user/token/:token", get(handlers::activate_user::activate_user_handler))
    .route("/api/v1/login", post(handlers::login::login_handler))
    .route("/api/v1/auth/refresh-token", get(handlers::refresh_token::refresh_access_token_handler))
    .route("/api/v1/auth/users/:userid", get(handlers::users::get_user_handler).route_layer(middleware::from_fn_with_state(
        app_state.clone(),
        jwt_auth::auth
        ,
    )),)
    .route("/api/v1/auth/users/:userid", patch(handlers::users::update_user_handler).route_layer(middleware::from_fn_with_state(
        app_state.clone(),
        jwt_auth::auth
        ,
    )),)
    .route("/api/v1/auth/logout", post(handlers::logout::logout_handler).route_layer(middleware::from_fn_with_state(
        app_state.clone(),
        jwt_auth::auth
        ,
    )),)
    .route("/", get(|| async { println!("home endpoint hit");"Welcome Home!" }))
    ;
    app.with_state(app_state.to_owned())
}