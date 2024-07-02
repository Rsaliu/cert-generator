use crate::app_state::AppState;
use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use axum_extra::extract::{
    cookie::{Cookie, SameSite},
    CookieJar,
};
use chrono::{Duration, Utc};
use crypto_lib::crypto::crypto::CryptoOp;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    default,
    str::FromStr,
    sync::{Arc, Mutex},
};
use store_lib::stores::{
    store::StoreTrait,
    token_store::{TokenPGStore, TokenRow},
    user_store::UserPGStore,
    user_store::UserRow,
};
use token_lib::token::token::{Token, TokenClaims, TokenType};
use user_lib::user::user::{User, UserRoles};
use uuid::Uuid;
pub async fn logout_handler(
    cookie_jar: CookieJar,
    State(data): State<Arc<Mutex<AppState>>>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let refresh_token = cookie_jar
        .get("refresh_token")
        .map(|cookie| cookie.value().to_string())
        .ok_or_else(|| {
            let error_response = serde_json::json!({
                "status": "fail",
                "message": "Token is invalid or session has expired"
            });
            (StatusCode::FORBIDDEN, Json(error_response))
        })?;
    let data = data.clone();
    let db = data.lock().unwrap().db.clone();
    let hmac_key = data.lock().unwrap().config.hmac_key.clone();

    // verify token

    let _token_data = CryptoOp::default()
        .verify_token(&hmac_key, refresh_token.clone())
        .await
        .map_err(|e| {
            let error_response = serde_json::json!({
                "status": "fail",
                "message": format!("Token verification error {}",e),
            });
            (StatusCode::UNAUTHORIZED, Json(error_response))
        })?;

    let token_store = TokenPGStore::default();

    // delete resfresh token
    token_store.delete_by_token(&db, refresh_token).await.map_err(|e| {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": format!("Token Not Deleted,{}",e),
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;
    let refresh_cookie = Cookie::build(("refresh_token", ""))
        .path("/")
        .max_age(time::Duration::minutes(-1))
        .same_site(SameSite::Strict)
        .http_only(true)
        .secure(false)
        .build();

    let mut headers = HeaderMap::new();
    headers.append(
        header::SET_COOKIE,
        refresh_cookie.to_string().parse().unwrap(),
    );
    let mut response = Response::new(json!({"status": "success"}).to_string());

    response.headers_mut().extend(headers);
    Ok(response)
}
