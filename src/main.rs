mod server;
mod app_state;
mod app_config;
use crate::server::router;
use app_state::AppState;
use app_config::AppConfig;
use axum::http::{
    header::{AUTHORIZATION, CONTENT_TYPE, ORIGIN},
    HeaderValue, Method,
};

use sqlx::{postgres::PgPoolOptions, Postgres,Pool};
use tower_http::cors::{CorsLayer,Any};
use std::{default, sync::{Arc,Mutex}};
use std::env;


async fn get_connection(db_url:&str)-> Result<Pool<Postgres>, Box<dyn std::error::Error>>
{
    let db = match PgPoolOptions::new()
        .max_connections(10)
        .connect(db_url)
        .await
    {
        Ok(pool) => {
            println!("Connection to the database is successful!");
            pool
        }
        Err(err) => {
            println!("Failed to connect to the database: {:?}", err);
            std::process::exit(1);
        }
    };
    Ok(db)
}

#[tokio::main]
async fn main() {
    // let origins = [
    //     "http://0.0.0.0:8080".parse::<HeaderValue>().unwrap(),
    //     format!(
    //         "http://{}",
    //         std::env::var("MY_EXTERNAL_IP").unwrap_or("localhost".to_string()),
    //     )
    //     .parse::<HeaderValue>()
    //     .unwrap(),
    // ];
    dotenvy::from_path(".env").expect("dot env error");
    let key = env::var("HMAC_KEY").expect("env variable error");
    let refresh_token_ttl_in_hr :usize= env::var("REFRESH_TOKEN_TTL_HR").expect("env variable error").parse::<usize>().expect("env error");
    let access_token_ttl_in_min:usize = env::var("ACCESS_TOKEN_TTL_MIN").expect("env variable error").parse::<usize>().expect("env error");
    let activation_token_ttl_in_hr:usize = env::var("ACTIVATION_TOKEN_TTL_HR").expect("env variable error").parse::<usize>().expect("env error");
    let app_state = Arc::new(Mutex::new(AppState{
        config: AppConfig{
            database_url:String::from("postgres://postgres@localhost/test_db"),
            hmac_key: key,
            refresh_token_ttl_in_hr, 
            access_token_ttl_in_min, 
            activation_token_ttl_in_hr 
        },
        db: get_connection("postgres://postgres@localhost/test_db").await.unwrap()
    }));
    let origins = [
        "http://0.0.0.0:8080".parse::<HeaderValue>().unwrap()
    ];
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::PUT,Method::POST, Method::DELETE])
        .allow_headers([AUTHORIZATION, CONTENT_TYPE, ORIGIN])
        .allow_credentials(true)
        .allow_origin(origins);
    let app = router::define_route(&app_state).layer(cors);

    // run our app with hyper, listening globally on port 3000
    let port = 3000;
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
        axum::serve(listener, app).await.unwrap();
    }).await;
}
