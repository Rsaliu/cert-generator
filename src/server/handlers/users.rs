use crate::app_state::AppState;
use axum::{
    extract::{State,Path},
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
    default, str::FromStr, sync::{Arc, Mutex}
};
use store_lib::stores::{
    store::StoreTrait, token_store::{TokenPGStore,TokenRow}, user_store::UserPGStore, user_store::UserRow,
};
use token_lib::token::token::{Token, TokenClaims, TokenType};
use user_lib::user::user::{User, UserRoles};
use uuid::Uuid;


pub async fn get_user_handler(
    State(data): State<Arc<Mutex<AppState>>>,
    Path(user_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let data = data.clone();
    let db = data.lock().unwrap().db.clone();
    let user_store = UserPGStore::default();
    let user_uuid = Uuid::from_str(&user_id).map_err(|e| {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "invalid ID",
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;  
    let user_data = user_store.get(&db,user_uuid).await.map_err(|_| {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "user not found",
        });
        (StatusCode::NOT_FOUND, Json(error_response))
    })?;
    let muser = user_data.first().unwrap().to_owned();

    let response = Response::new(
        json!(
        {
            "user": muser,
            "status": "success",
        })
        .to_string(),
    );
    Ok(response)
}


pub async fn update_user_handler(
    State(data): State<Arc<Mutex<AppState>>>,
    Path(user_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let data = data.clone();
    let db = data.lock().unwrap().db.clone();
    let user_store = UserPGStore::default();
    let user_uuid = Uuid::from_str(&user_id).map_err(|_| {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "invalid ID",
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;  
    user_store.patch(&db,user_uuid,body).await.map_err(|e| {
        println!("update error {}",e);
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "could not update user",
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;
    let response = Response::new(
        json!(
        {
            "status": "success",
        })
        .to_string(),
    );
    Ok(response)
}
