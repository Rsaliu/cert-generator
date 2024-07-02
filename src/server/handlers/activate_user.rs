use crate::app_state::AppState;
use chrono::{Duration, Utc};
use axum::{
    extract::{State,Path},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use crypto_lib::crypto::crypto::CryptoOp;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::types::Uuid;
use std::{
    default, path, str::FromStr, sync::{Arc, Mutex}
};
use store_lib::stores::{store::StoreTrait, token_store::TokenPGStore, user_store::UserPGStore,user_store::UserRow,token_store::TokenRow};
use user_lib::user::user::{User, UserRoles};
use token_lib::token::token::{Token, TokenClaims, TokenType};
pub async fn activate_user_handler(
    State(data): State<Arc<Mutex<AppState>>>,
    Path(token_string): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let data = data.clone();
    let db = data.lock().map_err(|e| {
        println!("{}",e);
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "lock failure"
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?.db.clone();
    let hmac_key = data.lock().map_err(|e| {
        println!("{}",e);
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "lock failure"
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?.config.hmac_key.clone();
    let token_data = CryptoOp::default().verify_token(&hmac_key, token_string.clone()).await.map_err(|e| {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": format!("Token verification error {}",e),
        });
        (StatusCode::UNAUTHORIZED, Json(error_response))
    })?;
    let token_json = serde_json::from_str(&token_data).map_err(|e| {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": format!("Token Format error,{}",e),
        });
        (StatusCode::UNAUTHORIZED, Json(error_response))
    })?;
    let token_claim:TokenClaims = serde_json::from_value(token_json).map_err(|e| {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": format!("Token verification error {}",e),
        });
        (StatusCode::UNAUTHORIZED, Json(error_response))
    })?;
    if token_claim.exp <= Utc::now().naive_utc(){
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Token expired".to_string(),
        });
        return Err((StatusCode::UNAUTHORIZED, Json(error_response)));
    }
    let token_store = TokenPGStore::default();
    let json_slug = json!({
        "token_string":token_string
    });
    let result = token_store.get_by_slug(&db, json_slug).await.map_err(|e| {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": format!("Token Not Found,{}",e),
        });
        (StatusCode::NOT_FOUND, Json(error_response))
    })?;
    println!("token returned is: {:?}",result);
    let result = result.first().ok_or_else(|| {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Token Not Found",
        });
        (StatusCode::NOT_FOUND, Json(error_response))})?;
    let token_row:TokenRow = serde_json::from_value(result.to_owned()).map_err(|e| {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": format!("Token error,{}",e),
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;
    if token_row.blacklisted{
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Token blacklisted".to_string(),
        });
        return Err((StatusCode::UNAUTHORIZED, Json(error_response)));
    }
    token_store.delete(&db, token_row.id).await.map_err(|e| {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": format!("Token error,{}",e),
        });
        (StatusCode::NOT_FOUND, Json(error_response))
    })?;

    let user_store = UserPGStore::default();
    let user_id = Uuid::from_str(&token_claim.sub).map_err(|e| {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": format!("Token Format error,{}",e),
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;
    let patch = serde_json::json!({
        "confirmed": true,
    });
    user_store.patch(&db,user_id,patch).await.map_err(|e| {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": format!("user retrieval Error,{}",e),
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;
    let mut response = Response::new(
        json!(
        {
            "status": "success",
        })
        .to_string(),
    );
    Ok(response)
}
