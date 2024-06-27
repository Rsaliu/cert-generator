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
use std::{
    default, path, sync::{Arc, Mutex}
};
use store_lib::stores::{store::StoreTrait, token_store::TokenPGStore, user_store::UserPGStore,user_store::UserRow,token_store::TokenRow};
use user_lib::user::user::{User, UserRoles};
use token_lib::token::token::{Token,TokenType};
pub async fn activate_user_handler(
    State(data): State<Arc<Mutex<AppState>>>,
    Path(token_string): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let data = data.clone();
    let db = data.lock().unwrap().db.clone();
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
    let user_store = UserPGStore::default();
    let patch = serde_json::json!({
        "confirmed": true,
    });
    user_store.patch(&db,token_row.user_id,patch).await.map_err(|e| {
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
