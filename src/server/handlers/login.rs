use crate::app_state::AppState;
use axum::{
    extract::{State},
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
    store::StoreTrait, token_store::TokenPGStore, user_store::UserPGStore, user_store::UserRow,
};
use token_lib::token::token::{Token, TokenType,TokenClaims};
use user_lib::user::user::{User, UserRoles};
use uuid::Uuid;
#[derive(Debug, Deserialize)]
pub struct LoginSchema {
    #[serde(rename = "username")]
    pub username: String,
    #[serde(rename = "password")]
    pub password: String,
}

pub async fn login_handler(
    State(data): State<Arc<Mutex<AppState>>>,
    Json(body): Json<LoginSchema>,
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
    let refresh_token_ttl_in_hr: usize = data.lock().unwrap().config.refresh_token_ttl_in_hr;
    let access_token_ttl_in_min: usize = data.lock().unwrap().config.access_token_ttl_in_min;

    let user_store = UserPGStore::default();
    println!("body received: {:?}", body);

    // retrieve user
    let user_json = user_store
        .get_by_username(&db, &body.username)
        .await
        .map_err(|e| {
            let error_response = serde_json::json!({
                "status": "fail",
                "message": format!("user not found,{}",e),
            });
            (StatusCode::NOT_FOUND, Json(error_response))
        })?;

    let user_from_db: UserRow = serde_json::from_value(user_json).map_err(|e| {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": format!("User conversion error {}",e),
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;
    let user_from_db: User = user_from_db.into();
    // Hash password entered
    let crypto_op = CryptoOp::default();
    let p_hash = crypto_op
        .generate_hash(body.password.clone())
        .await
        .map_err(|e| {
            let error_response = serde_json::json!({
                "status": "fail",
                "message": format!("crypto failed,{}",e),
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })?;

    //compare password hash
    if p_hash != user_from_db.get_password() {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "incorrect credential",
        });
        return Err((StatusCode::UNAUTHORIZED, Json(error_response)));
    }

    let hmac_key = data.lock().unwrap().config.hmac_key.to_string();

    // Generate access token 
    let expiry = (Utc::now() + Duration::minutes(access_token_ttl_in_min as i64)).naive_utc();
    println!("access token expiry slated for {:?}",expiry);
    let token_claim = TokenClaims{
        sub: user_from_db.get_id().to_string(),
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


    let token_store = TokenPGStore::default();

    // Generate refresh token
    let expiry = (Utc::now() + Duration::minutes(refresh_token_ttl_in_hr as i64)).naive_utc();
    let token_claim = TokenClaims{
        sub: user_from_db.get_id().to_string(),
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
    let refresh_token_string = crypto_op
        .generate_token(&hmac_key, token_claim_string.clone())
        .await
        .map_err(|e| {
            let error_response = serde_json::json!({
                "status": "fail",
                "message": format!("Crypto error,{}",e),
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })?;

        let new_token = Token::new(
            refresh_token_string.clone(),
            TokenType::RefreshToken
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
                "message": format!("Could not store refresh data,{}",e),
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })?;
    // TODO Handle Email Sending
    let mut response = Response::new(
        json!(
        {
            "access_token": access_token_string,
            "status": "success",
        })
        .to_string(),
    );
    let refresh_cookie = Cookie::build((
        "refresh_token",
        refresh_token_string.clone(),
    ))
    .path("/")
    .max_age(time::Duration::minutes(refresh_token_ttl_in_hr as i64))
    .same_site(SameSite::Strict)
    .http_only(true)
    //TODO change this in release
    .secure(false)
    .build();
    let mut headers = HeaderMap::new();
    headers.append(
        header::SET_COOKIE,
        refresh_cookie.to_string().parse().unwrap(),
    );

    response.headers_mut().extend(headers);
    Ok(response)
}
