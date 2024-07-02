mod server;
mod app_state;
mod app_config;
use crate::server::router;
use app_state::AppState;
use app_config::{AppConfig};
use crypto_lib::crypto::crypto::CertConfig;
use axum::http::{
    header::{AUTHORIZATION, CONTENT_TYPE, ORIGIN},
    HeaderValue, Method,
};

use sqlx::{postgres::PgPoolOptions, Postgres,Pool};
use tower_http::cors::{CorsLayer,Any};
use std::{default, sync::{Arc,Mutex}};
use std::env;
use std::fs::File;
use std::io::Read;

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

use std::fmt;

#[derive(PartialEq)]
enum AppEnv {
    Dev,
    Prod,
}
impl fmt::Display for AppEnv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppEnv::Dev => write!(f, "dev"),
            AppEnv::Prod => write!(f, "prod"),
        }
    }
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
    let app_env = match env::var("APP_ENV") {
        Ok(v) if v == "prod" => AppEnv::Prod,
        _ => AppEnv::Dev,
    };
    println!("Running in {} mode",app_env);
    if app_env == AppEnv::Dev {
        dotenvy::from_path(".env").expect("dot env error");
        let key = env::var("HMAC_KEY").expect("env variable error");
        let refresh_token_ttl_in_hr :usize= env::var("REFRESH_TOKEN_TTL_HR").expect("env variable error").parse::<usize>().expect("env error");
        let access_token_ttl_in_min:usize = env::var("ACCESS_TOKEN_TTL_MIN").expect("env variable error").parse::<usize>().expect("env error");
        let activation_token_ttl_in_hr:usize = env::var("ACTIVATION_TOKEN_TTL_HR").expect("env variable error").parse::<usize>().expect("env error");
        let mqtt_host_common_name:String = env::var("MQTT_HOST_CN").expect("env variable error");
        let mqtt_root_ca_path:String = env::var("MQTT_ROOT_CA_PATH").expect("env variable error");
        let mqtt_server_key_path:String = env::var("MQTT_SERVER_KEY_PATH").expect("env variable error");
        let database_url:String = env::var("DATABASE_URL").expect("env variable error");
        let server_url:String = env::var("SERVER_URL").expect("env variable error");
        let mut ca_file = File::open(mqtt_root_ca_path).expect("read failure");
        let mut ca_buf = Vec::new();
        ca_file.read_to_end(&mut ca_buf).expect("read error");
        let mut key_file = File::open(mqtt_server_key_path).expect("read failure");
        let mut key_buf = Vec::new();
        key_file.read_to_end(&mut key_buf).expect("read error");
        let mqtt_cert_details = CertConfig::new(mqtt_host_common_name, ca_buf.clone(), key_buf);   
        let app_state = Arc::new(Mutex::new(AppState{
            config: AppConfig{
                database_url:database_url.clone(),
                hmac_key: key,
                refresh_token_ttl_in_hr, 
                access_token_ttl_in_min, 
                activation_token_ttl_in_hr,
                mqtt_cert_details
            },
            db: get_connection(database_url.as_str()).await.unwrap()
        }));
        let origins = [
            server_url.parse::<HeaderValue>().unwrap()
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
        let handle = tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
            axum::serve(listener, app).await.unwrap();
        }).await;
        handle.unwrap();
    }


}
