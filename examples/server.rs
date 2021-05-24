//! Example of auth flow.
//!
//! To use this, set the environment variables `CLIENT_ID` and `CLIENT_SECRET` to their respective values.
//! See <https://dev.twitch.tv/docs/authentication#registration> for more information
//!
//! You'll need to add `http://localhost:10666/twitch/token` to your redirect URIs. (You can also override the url with the first argument passed to the executable)
use std::env;
use twitch_oauth2_auth_flow::auth_flow_surf;

#[tokio::main]
async fn main() {
    let _ = dotenv::dotenv();
    let client_id = get_var("CLIENT_ID");
    let client_secret = get_var("CLIENT_SECRET");
    let redirect_url = env::args()
        .nth(1)
        .unwrap_or_else(|| "http://localhost:10666/twitch/token".to_string());
    let scopes = None;
    let res = auth_flow_surf(&client_id, &client_secret, scopes, &redirect_url);
    println!("got result: {:?}", res);
}

fn get_var(var: &'static str) -> String {
    env::var(var).unwrap_or_else(|e| panic!("Could not get env {} - {}", var, e))
}
