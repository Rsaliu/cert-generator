use crate::app_state::AppState;
use chrono::{Duration, Utc};
use axum::{
    extract::{Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware::Next,
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
use user_lib::user::user::{User, UserRoles};
use token_lib::token::token::{Token,TokenType,TokenClaims};

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub status: &'static str,
    pub message: String,
}

pub async fn auth(
    State(data): State<Arc<Mutex<AppState>>>,
    mut req: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    println!("inside jwt auth");
    let data = data.clone();
    let db = data.lock().unwrap().db.clone();
    let hmac_key = data.lock().unwrap().config.hmac_key.clone();
    let access_token = req
    .headers()
    .get(header::AUTHORIZATION)
    .and_then(|auth_header| auth_header.to_str().ok())
    .and_then(|auth_value| {
        auth_value
            .strip_prefix("Bearer ")
            .map(|stripped| stripped.to_owned())
    });

    let access_token = access_token.ok_or_else(|| {
        let error_response = ErrorResponse {
            status: "fail",
            message: "You are not logged in, please provide token".to_string(),
        };
        (StatusCode::UNAUTHORIZED, Json(error_response))
    })?;
    
    let token_data = CryptoOp::default().verify_token(&hmac_key, access_token.clone()).await.map_err(|e| {
        let error_response = ErrorResponse{
            status: "fail",
            message: format!("Token verification error {}",e),
        };
        (StatusCode::UNAUTHORIZED, Json(error_response))
    })?;
    let token_json = serde_json::from_str(&token_data).map_err(|e| {
        let error_response = ErrorResponse{
            status: "fail",
            message: format!("Token format error {}",e),
        };
        (StatusCode::UNAUTHORIZED, Json(error_response))
    })?;
    let token_claim:TokenClaims = serde_json::from_value(token_json).map_err(|e| {
        let error_response = ErrorResponse{
            status: "fail",
            message: format!("Token format error {}",e),
        };
        (StatusCode::UNAUTHORIZED, Json(error_response))
    })?;
    println!("token expiry is: {:?}",token_claim.exp );
    if token_claim.exp <= Utc::now().naive_utc(){
        let error_response = ErrorResponse{
            status: "fail",
            message: "Token expired".to_string(),
        };
        return Err((StatusCode::UNAUTHORIZED, Json(error_response)));
    }
    Ok(next.run(req).await)
}