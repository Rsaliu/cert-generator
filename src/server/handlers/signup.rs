use crate::app_state::AppState;
use chrono::{Duration, Utc};
use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use crypto_lib::crypto::crypto::CryptoOp;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    default,
    sync::{Arc, Mutex},
};
use store_lib::stores::{store::StoreTrait, token_store::TokenPGStore, user_store::UserPGStore,user_store::UserRow};
use user_lib::user::user::{User, UserRoles};
use token_lib::token::token::{Token,TokenType};
#[derive(Debug, Deserialize)]
pub struct SignupSchema {
    #[serde(rename = "username")]
    pub username: String,
    #[serde(rename = "email")]
    pub email: String,
    #[serde(rename = "password")]
    pub password: String,
}

pub async fn signup_handler(
    State(data): State<Arc<Mutex<AppState>>>,
    Json(body): Json<SignupSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let data = data.clone();
    let db = data.lock().unwrap().db.clone();
    let user_store = UserPGStore::default();
    println!("body received: {:?}", body);
    let default_user_role = UserRoles::Normal;
    let new_user = User::new(body.username, body.password, body.email, default_user_role);
    let user_json = serde_json::to_value(&new_user).map_err(|e| {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": format!("Invalid email, password or username,{}",e),
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;
    user_store.insert(&db, user_json).await.map_err(|e| {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": format!("Could not store user data,{}",e),
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;
    let user_data = user_store.get_by_username(&db,new_user.get_name()).await.map_err(|e| {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": format!("user retrieval Error,{}",e),
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;
    let user_row:UserRow = serde_json::from_value(user_data).map_err(|e| {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": format!("user retrieval Error,{}",e),
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;
    
    let hmac_key = data.lock().unwrap().config.hmac_key.to_string();
    let crypto_op = CryptoOp::default();
    let token_string = crypto_op
        .generate_token(&hmac_key, new_user.get_name().to_string())
        .await
        .map_err(|e| {
            let error_response = serde_json::json!({
                "status": "fail",
                "message": format!("Crypto error,{}",e),
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })?;
    let activation_token_ttl_in_hr:usize = data.lock().unwrap().config.activation_token_ttl_in_hr;
    let expiry = (Utc::now()+Duration::hours(activation_token_ttl_in_hr as i64)).naive_utc();
    let token_store = TokenPGStore::default();
    let new_token = Token::new(
        user_row.id,
        token_string,
        expiry,
        TokenType::ActivationToken
    );
    let token_json = serde_json::to_value(&new_token).map_err(|e| {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": format!("Json error,{}",e),
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;
    token_store.insert(&db, token_json).await.map_err(|e| {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": format!("Could not store activation data,{}",e),
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;
    // TODO Handle Email Sending
    let mut response = Response::new(
        json!(
        {
            "status": "success",
        })
        .to_string(),
    );
    Ok(response)
}
