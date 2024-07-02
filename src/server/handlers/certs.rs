use crate::app_state::AppState;
use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};

use crypto_lib::crypto::crypto::CryptoOp;
use serde_json::json;
use std::{
    sync::{Arc, Mutex},
};

pub async fn cert_gen_handler(
    State(data): State<Arc<Mutex<AppState>>>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let data = data.clone();
    let config = data.lock().map_err(|e| {
        println!("{}", e);
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "lock failure"
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;
    let crypto_op = CryptoOp::default();
    let client_credential = crypto_op
        .generate_rsa_x509(&config.config.mqtt_cert_details)
        .map_err(|e| {
            println!("{e}");
            let error_response = serde_json::json!({
                "status": "fail",
                "message": "Could not generate cert"
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })?;
    let client_cert_string = String::from_utf8_lossy(client_credential.get_cert());
    let client_key_string = String::from_utf8_lossy(client_credential.get_key());
    let ca_string = String::from_utf8_lossy(&config.config.mqtt_cert_details.root_ca);
    println!("client cert is: {:?}", client_cert_string);
    println!("client key is: {:?}", client_key_string);
    println!("ca is: {:?}", ca_string);
    let response = Response::new(
        json!(
        {
            "ca":ca_string,
            "client cert": client_cert_string,
            "client_key":client_key_string,
            "status": "success",
        })
        .to_string(),
    );
    Ok(response)
}


