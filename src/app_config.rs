
pub struct AppConfig{
    pub database_url: String,
    pub hmac_key: String,
    pub refresh_token_ttl_in_hr: usize, 
    pub access_token_ttl_in_min: usize, 
    pub activation_token_ttl_in_hr: usize, 
}