use crate::app_state::AppState;
use axum::{
    extract::State,
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
    sync::{Arc, Mutex},
};
use store_lib::stores::{
    store::StoreTrait, token_store::{TokenPGStore,TokenRow}, user_store::UserPGStore, user_store::UserRow,
};
use token_lib::token::token::{Token, TokenClaims, TokenType};
use user_lib::user::user::{User, UserRoles};
use uuid::Uuid;

pub async fn refresh_access_token_handler(
    cookie_jar: CookieJar,
    State(data): State<Arc<Mutex<AppState>>>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let token_string = cookie_jar
        .get("refresh_token")
        .map(|cookie| cookie.value().to_string())
        .ok_or_else(|| {
            let error_response = serde_json::json!({
                "status": "fail",
                "message": "could not refresh access token"
            });
            (StatusCode::FORBIDDEN, Json(error_response))
        })?;
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

    // verify token

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
            "message": format!("Token format error {}",e),
        });
        (StatusCode::UNAUTHORIZED, Json(error_response))
    })?;
    let token_claim:TokenClaims = serde_json::from_value(token_json).map_err(|e| {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": format!("Token format error {}",e),
        });
        (StatusCode::UNAUTHORIZED, Json(error_response))
    })?;

    if token_claim.exp <= Utc::now().naive_utc(){
        let error_response =  serde_json::json!({
            "status": "fail",
            "message": "Token expired".to_string(),
        });
        return Err((StatusCode::UNAUTHORIZED, Json(error_response)));
    }
    // search token

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

    // check if token is blacklisted
    if token_row.blacklisted{
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Token blacklisted".to_string(),
        });
        return Err((StatusCode::UNAUTHORIZED, Json(error_response)));
    }


    // Generate new access token
    let access_token_ttl_in_min: usize = data.lock().unwrap().config.access_token_ttl_in_min;
    let expiry = (Utc::now() + Duration::minutes(access_token_ttl_in_min as i64)).naive_utc();
    println!("access token expiry slated for {:?}",expiry);
    let token_claim = TokenClaims{
        sub: token_claim.sub,
        token_uuid: Uuid::new_v4(),
        exp:expiry,
        iat: Utc::now().naive_utc(),
        nbf: Utc::now().naive_utc()
    };
    let token_claim_string = serde_json::to_string(&token_claim).map_err(|e| {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": format!("Serialization error,{}",e),
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;
    let crypto_op = CryptoOp::default();

    let access_token_string = crypto_op
        .generate_token(&hmac_key, token_claim_string.clone())
        .await
        .map_err(|e| {
            let error_response = serde_json::json!({
                "status": "fail",
                "message": format!("Crypto error,{}",e),
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })?;



    let response = Response::new(
        json!(
        {
            "access_token": access_token_string,
            "status": "success",
        })
        .to_string(),
    );
    Ok(response)
}
