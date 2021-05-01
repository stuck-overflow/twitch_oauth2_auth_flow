use futures::executor::block_on;
use log::{debug, error};
use tiny_http::{Response, Server, StatusCode};
use twitch_oauth2::{
    client::SurfError,
    tokens::{errors::UserTokenExchangeError, UserTokenBuilder},
    ClientId, ClientSecret, CsrfToken, Scope, UserToken,
};
use url::Url;

/// Errors for [`auth_flow`]
#[derive(Debug, thiserror::Error)]
pub enum AuthFlowError {
    #[error(transparent)]
    HookError(#[from] HookError),
    #[error("could not parse url")]
    UrlParseError(#[from] url::ParseError),
}

/// Hook errors for [`TwitchAuthHook`]
#[derive(Debug, thiserror::Error)]
pub enum HookError {
    #[error("when constructing http server")]
    TinyHttpError(#[source] Box<(dyn std::error::Error + Sync + Send + 'static)>),
    #[error("could not parse url")]
    UrlParseError(#[from] url::ParseError),
    #[error("failed to do IO operation")]
    IoError(#[from] std::io::Error),
    #[error("talking with twitch authentication failed")]
    ExchangeError(#[from] UserTokenExchangeError<SurfError>),
}

/// Twitch authentication flow.
///
/// This token will only be valid for around 4 hours, but you can refresh the token with [`UserToken::refresh_token`](twitch_oauth2::TwitchToken::refresh_token)
pub fn auth_flow(
    client_id: &str,
    client_secret: &str,
    scopes: Option<Vec<Scope>>,
    redirect_url: &str,
) -> Result<UserToken, AuthFlowError> {
    let redirect_url = Url::parse(&redirect_url)?;
    let mut hook = TwitchAuthHook::new(
        String::from(client_id),
        String::from(client_secret),
        scopes,
        redirect_url,
    )?;
    let (url, _) = hook.generate_url();
    println!(
        "To obtain an authentication token, please visit\n{}",
        url.as_str().to_owned()
    );
    block_on(async { hook.receive_auth_token().await }).map_err(Into::into)
}

/// Token generator using [OAuth authorization code flow](https://dev.twitch.tv/docs/authentication/getting-tokens-oauth/#oauth-authorization-code-flow)
///
/// Spins up a small webserver that listens for a response from the user after they are redirected to the redirect URL by twitch.
///
/// See [`auth_flow`] for a more integrated way of using this.
///
/// Make a new [`TwitchAuthHook`] and call [`generate_url()`](TwitchAuthHook::generate_url) and make the user navigate to the url.
/// Retrieve the token with [`receive_auth_token`](TwitchAuthHook::receive_auth_token).
///
/// # Example
///
/// ```rust, no_run
/// use twitch_oauth2_auth_flow::TwitchAuthHook;
/// use twitch_oauth2::{TwitchToken, UserToken, Scope};
/// use url::Url;
///
/// let mut hook = TwitchAuthHook::new(
///     "my_client_id".to_string(),
///     "my_client_secret".to_string(),
///     vec![Scope::ChatRead, Scope::ChatEdit, Scope::ChannelModerate, Scope::ModerationRead]
///     Url::parse("http://localhost:8081/twitch/token")?,
/// )?;
///
/// let (url, _) = hook.generate_url();
/// give_url_to_user(url);
/// let token = hook.receive_auth_token()?;
/// # fn give_url_to_user(_: impl std::any::Any ) {}
/// # Ok::<(), Box<std::error::Error + 'static>>(())
/// ```
pub struct TwitchAuthHook {
    builder: UserTokenBuilder,
    redirect_url: Url,
    port: u16,
}

impl TwitchAuthHook {
    /// Construct a new [`TwitchAuthHook`]
    pub fn new(
        client_id: String,
        client_secret: String,
        scopes: impl Into<Option<Vec<Scope>>>,
        redirect_url: Url,
    ) -> Result<TwitchAuthHook, HookError> {
        let redirect = twitch_oauth2::RedirectUrl::from_url(redirect_url.clone());
        let port = redirect.url().port_or_known_default().unwrap_or(80);
        let mut builder = UserToken::builder(
            ClientId::new(client_id),
            ClientSecret::new(client_secret),
            redirect,
        )
        .expect("unexpected failure to construct urls to twitch")
        .force_verify(true);
        if let Some(scopes) = scopes.into() {
            builder = builder.set_scopes(scopes);
        }
        Ok(TwitchAuthHook {
            builder,
            redirect_url,
            port,
        })
    }

    /// Generate the url and csrf token associated with this [`TwitchAuthHook`]
    pub fn generate_url(&mut self) -> (Url, CsrfToken) {
        self.builder.generate_url()
    }

    /// Override the implicit port for the server as given by the redirect url.
    ///
    /// Useful if the application is behind a reverse-proxy
    pub fn set_port(&mut self, port: u16) {
        self.port = port;
    }

    /// Spin up a server to retrieve the token from the user.
    ///
    /// This token will only be valid for around 4 hours, but you can refresh the token with [`UserToken::refresh_token`](twitch_oauth2::TwitchToken::refresh_token)
    pub async fn receive_auth_token(self) -> Result<UserToken, HookError> {
        let http_server =
            Server::http(format!("0.0.0.0:{}", self.port)).map_err(HookError::TinyHttpError)?;
        let (code, state) = loop {
            match http_server.recv() {
                Ok(rq) => {
                    debug!("request: {:?}", rq);
                    let url = format!(
                        "http://localhost:{}{}",
                        http_server.server_addr().port(),
                        rq.url()
                    );
                    let url = Url::parse(&url)?;
                    // Check if the path the user navigated to matches the redirect url.
                    if url.path() != self.redirect_url.path() {
                        rq.respond(Response::from_string("KO").with_status_code(StatusCode(500)))?;
                        continue;
                    }

                    let query: std::collections::HashMap<_, _> = url.query_pairs().collect();

                    match (query.get("code"), query.get("state")) {
                        (Some(code), Some(state)) => {
                            rq.respond(Response::from_string("OK"))?;
                            break (code.to_string(), state.to_string());
                        }
                        _ => match (query.get("error"), query.get("error_description")) {
                            (None, None) => {
                                rq.respond(
                                    Response::from_string("KO").with_status_code(StatusCode(500)),
                                )?;
                                continue;
                            }
                            (e, d) => {
                                rq.respond(
                                    Response::from_string(&format!(
                                        "Error: {} - {}",
                                        e.map(|e| e.as_ref()).unwrap_or(""),
                                        d.map(|e| e.as_ref()).unwrap_or("")
                                    ))
                                    .with_status_code(400),
                                )?;
                                continue;
                            }
                        },
                    }
                }
                Err(e) => {
                    error!("error: {}", e)
                }
            }
        };
        self.builder
            .get_user_token(twitch_oauth2::client::surf_http_client, &state, &code)
            .await
            .map_err(Into::into)
    }
}
