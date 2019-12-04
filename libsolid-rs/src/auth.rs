use failure::Fallible;
use serde::{de::DeserializeOwned, Serialize};

pub trait AuthenticatedClient<T, LoginOptions, S>: crate::Client<S>
where
    S: Serialize + DeserializeOwned,
{
    fn login(login_options: LoginOptions) -> Fallible<T>;
}

/// This module implements the WebID-OIDC protocol
pub mod webid_oidc {
    use crate::auth::AuthenticatedClient;
    use crate::ProviderID;
    use failure::{bail, Fallible, ResultExt};
    use openidconnect::core::{
        CoreClient, CoreClientRegistrationRequest, CoreProviderMetadata, CoreResponseType,
    };
    use openidconnect::registration::EmptyAdditionalClientMetadata;
    use openidconnect::reqwest::http_client as oidc_http_client;
    use openidconnect::{
        AccessToken, AccessTokenHash, AuthenticationFlow, AuthorizationCode, ClientId,
        ClientSecret, CsrfToken, IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge,
        RegistrationUrl, Scope, TokenResponse,
    };
    use serde::{Deserialize, Serialize};
    use std::convert::TryInto;
    use std::sync::mpsc::Receiver;
    use std::sync::mpsc::Sender;

    use std::collections::{HashMap, HashSet};

    type Result<T> = Fallible<T>;

    pub type ProviderMetadata = CoreProviderMetadata;

    #[derive(Serialize, Deserialize)]
    pub struct Provider {
        id: ProviderID,
        metadata: ProviderMetadata,
    }

    #[derive(Serialize, Deserialize)]
    pub struct RegistrationCredentials {
        client_id: String,
        client_secret: String,
    }

    #[derive(Serialize, Deserialize)]
    pub struct Registration {
        provider: Provider,
        credentials: RegistrationCredentials,

        // TODO: verify if (and why) we need to store this
        redirect_url: String,
    }

    impl TryInto<openidconnect::core::CoreClient> for &Registration {
        type Error = failure::Error;

        fn try_into(self) -> Fallible<openidconnect::core::CoreClient> {
            unimplemented!()
        }
    }

    pub type WebID = String;

    #[derive(Serialize, Deserialize)]
    pub struct AccessCredentials {
        access_token: AccessToken,
        id_token_claims: openidconnect::IdTokenClaims<
            openidconnect::EmptyAdditionalClaims,
            openidconnect::core::CoreGenderClaim,
        >,
        authorized_scopes: Option<HashSet<Scope>>,
    }

    impl AccessCredentials {
        /// Derive the WebID from the IdToken claim
        pub fn webid(&self) -> WebID {
            // TODO: Derive a WebID URI from the id_token as described at https://github.com/solid/webid-oidc-spec/blob/0e6da67a624a4d09ab85e28bafe85da33f860a61/README.md#deriving-webid-uri-from-id-token
            self.id_token_claims.subject().to_string()
        }
    }

    /// Client for talking to one WebIdOIDC provider and can handles multiple users' access credentials.
    pub struct Client {
        oidc_client: Option<openidconnect::core::CoreClient>,
        state: ClientState,
    }

    #[derive(Serialize, Deserialize)]
    pub struct ClientState {
        registration: Registration,
        access_tokens: HashMap<WebID, AccessCredentials>,
    }

    pub struct LoginOptions {
        provider_url: ProviderID,
        scopes: Vec<String>,
        callback_url: url::Url,
        authorize_url_sender: Sender<url::Url>,
        callback_values_receiver: Receiver<callback_server::CallbackValues>,
    }

    impl AuthenticatedClient<Client, LoginOptions, ClientState> for Client {
        /// Initiates a (by default) interactive login to the given provider
        fn login(login_options: LoginOptions) -> Result<Self> {
            let provider_metadata = Self::discover(login_options.provider_url.clone())
                .context(format!("discover provider {}", &login_options.provider_url))?;

            let registration = {
                let registration_credentials =
                    Self::register(&provider_metadata, &login_options.callback_url).context(
                        format!("registration with provider {}", &login_options.provider_url),
                    )?;

                Registration {
                    provider: Provider {
                        id: login_options.provider_url,
                        metadata: provider_metadata,
                    },
                    credentials: registration_credentials,
                    redirect_url: login_options.callback_url.to_string(),
                }
            };

            // Create an OpenID Connect client by specifying the client ID, client secret, authorization URL
            // and token URL.
            let oidc_client = CoreClient::from_provider_metadata(
                registration.provider.metadata.clone(),
                ClientId::new(registration.credentials.client_id.clone()),
                Some(ClientSecret::new(
                    registration.credentials.client_secret.clone(),
                )),
            )
            // Set the URL the user will be redirected to after the authorization process.
            .set_redirect_uri(
                openidconnect::RedirectUrl::new(registration.redirect_url.clone())
                    .context("setting redirect url")?,
            );

            let credentials = Self::authorize(
                &oidc_client,
                login_options.scopes.into_iter().map(Scope::new).collect(),
                login_options.authorize_url_sender,
                login_options.callback_values_receiver,
            )
            .context("authorization")?;

            let access_tokens = vec![("TODO: some ressource id here".to_string(), credentials)]
                .into_iter()
                .collect::<HashMap<WebID, AccessCredentials>>();

            Ok(Client {
                oidc_client: Some(oidc_client),
                state: ClientState {
                    registration,
                    access_tokens,
                },
            })
        }
    }

    impl crate::Client<ClientState> for Client {
        /// Get the Client's ProviderId.
        fn provider_id(&self) -> &ProviderID {
            &self.state.registration.provider.id
        }

        fn state(&self) -> &ClientState {
            &self.state
        }
    }

    impl Client {
        pub fn from_state(state: ClientState) -> Result<Self> {
            let client = Client {
                oidc_client: Some((&state.registration).try_into()?),
                state,
            };

            Ok(client)
        }

        fn discover(provider_url: ProviderID) -> Result<ProviderMetadata> {
            Ok(
                CoreProviderMetadata::discover(&IssuerUrl::new(provider_url)?, oidc_http_client)
                    .context("provider metadata discovery")?,
            )
        }

        fn register(
            provider_metadata: &CoreProviderMetadata,
            redirect_url: &url::Url,
        ) -> Result<RegistrationCredentials> {
            let registration = CoreClientRegistrationRequest::new(
                vec![openidconnect::RedirectUrl::new(redirect_url.to_string())?],
                EmptyAdditionalClientMetadata::default(),
            );

            let registration_url = provider_metadata
                .registration_endpoint()
                // TODO: remove unwrap
                .unwrap()
                .to_string();

            let response = registration
                .register(
                    &RegistrationUrl::new(registration_url.clone())
                        .context("new registration url")?,
                    oidc_http_client,
                )
                .context(format!("registration at {}", &registration_url))?;

            Ok(RegistrationCredentials {
                client_id: response.client_id().as_str().to_string(),
                client_secret: response
                    .client_secret()
                    // TODO: remove unwrap
                    .unwrap()
                    .secret()
                    .to_string(),
            })
        }

        fn authorize(
            oidc_client: &CoreClient,
            requested_scopes: HashSet<Scope>,
            authorize_url_sender: Sender<url::Url>,
            callback_values_receiver: Receiver<callback_server::CallbackValues>,
        ) -> Result<AccessCredentials> {
            // Generate a PKCE challenge.
            let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

            // Generate the full authorization URL.
            let (auth_url, csrf_token, nonce) = {
                let authorization_request = oidc_client
                    .authorize_url(
                        AuthenticationFlow::<CoreResponseType>::Hybrid(vec![
                            openidconnect::core::CoreResponseType::Code,
                            // TODO: this currently causes the response to not contain `state`. research if we need this at all, as the procedure seems fine without it.
                            // openidconnect::core::CoreResponseType::IdToken,
                        ]),
                        CsrfToken::new_random,
                        Nonce::new_random,
                    )
                    .set_pkce_challenge(pkce_challenge);

                &requested_scopes
                    .iter()
                    .cloned()
                    .fold(
                        authorization_request,
                        |final_authorization_request, scope| {
                            final_authorization_request.add_scope(scope)
                        },
                    )
                    .url()
            };

            // Pass the auth_url to the caller.
            authorize_url_sender.send(auth_url.clone())?;

            eprintln!("[Client::login] sent authorize url {}", &auth_url);

            // Wait for the callback values.
            let code = callback_values_receiver
                .recv()
                .map_err(failure::Error::from)
                .and_then(|callback_values| {
                    // For security reasons, verify that the `state` parameter
                    // returned by the server matches `csrf_state`.
                    match callback_values.get("state") {
                        Some(state) => {
                            let token = CsrfToken::new(state.to_string());
                            if token.secret() != csrf_token.secret() {
                                bail!("received state {}, expected: {:?}", state, &csrf_token);
                            }
                        }
                        None => bail!("no state in callback values: {:?}", callback_values),
                    };

                    callback_values
                        .get("code")
                        .ok_or_else(|| {
                            failure::err_msg(format!(
                                "no code in callback values: {:?}",
                                callback_values
                            ))
                        })
                        .map(Into::<String>::into)
                })
                .context("receiving callback values")?;

            // Exchange the code for an access token and ID token.
            let token_response = oidc_client
                .exchange_code(AuthorizationCode::new(code))
                .set_pkce_verifier(pkce_verifier)
                .request(oidc_http_client)
                .context("exchange code for token")?;

            // Verify the authenticity and nonce of the access token and the ID
            // token claims.
            let (access_token, id_token_claims) = token_response
                .id_token()
                .ok_or_else(|| failure::err_msg("no id_token in response"))
                .and_then(|id_token| {
                    let access_token = token_response.access_token();

                    // The authenticated user's identity is now available. See
                    // the IdTokenClaims struct for a complete listing of the
                    // available claims.
                    let id_token_claims = id_token
                        .claims(&oidc_client.id_token_verifier(), nonce)
                        .map_err(failure::Error::from)
                        .and_then(|id_token_claims| {
                            // Verify the access token hash to ensure that the
                            // access token hasn't been substituted for another
                            // user's.
                            if let Some(expected_access_token_hash) =
                                id_token_claims.access_token_hash()
                            {
                                let actual_access_token_hash = AccessTokenHash::from_token(
                                    access_token,
                                    &id_token.signing_alg()?,
                                )?;
                                if actual_access_token_hash != *expected_access_token_hash {
                                    bail!("Invalid access token");
                                }
                            }

                            Ok(id_token_claims)
                        })?;

                    Ok((access_token.clone(), id_token_claims.clone()))
                })?;

            // Verify which scopes given in the response https://tools.ietf.org/html/rfc6749#section-3.3.
            let authorized_scopes = token_response.scopes().map(|authorized_scopes| {
                let authorized_scopes = authorized_scopes
                    .iter()
                    .cloned()
                    // Convert to a HashSet for efficient comparison
                    .collect::<HashSet<_>>();

                if authorized_scopes != requested_scopes {
                    eprintln!(
                        "[Client::login] [WARNING] requested scopes {:?} but was authorized is for {:?}",
                        requested_scopes, authorized_scopes,
                    )
                };

                authorized_scopes
            });

            // TODO: possibly include these?
            // TODO: See the OAuth2TokenResponse trait for a listing of other available fields such as
            let _token_type = token_response.token_type();
            let _refresh_token = token_response.refresh_token();
            let _expires_in = token_response.expires_in();

            Ok(AccessCredentials {
                access_token,
                id_token_claims,
                authorized_scopes,
            })
        }
    }

    pub mod callback_server {
        use super::*;
        use actix_web::{web, App, HttpServer, Responder};
        use std::str::FromStr;
        use std::sync::Mutex;

        pub struct CallbackServer {
            bind_addr: String,
            url: url::Url,
            callback_values_sender: Sender<CallbackValues>,
            server: Option<actix_server::Server>,
        }

        impl CallbackServer {
            pub fn url(&self) -> &url::Url {
                &self.url
            }

            pub fn try_new(
                bind_addr: String,
                callback_values_sender: Sender<CallbackValues>,
            ) -> Fallible<Self> {
                Ok(Self {
                    url: url::Url::from_str(&format!("http://{}", &bind_addr))?,
                    bind_addr,
                    callback_values_sender,
                    server: None,
                })
            }

            pub fn spawn(&mut self) -> Fallible<()> {
                if self.server.is_some() {
                    bail!("server is already running")
                }

                let (tx_server, rx_server) = std::sync::mpsc::channel();
                {
                    let bind_addr = self.bind_addr.clone();

                    let app_data = web::Data::new(Mutex::new(self.callback_values_sender.clone()));

                    std::thread::spawn(move || {
                        let sys = actix_rt::System::new("callback-server");

                        let server = HttpServer::new(move || {
                            App::new()
                                .register_data(app_data.clone())
                                .service(web::resource("/").to(Self::index))
                        })
                        .bind(&bind_addr)
                        .context(format!("binding addr  {}", &bind_addr))
                        // TODO: remove unwrap
                        .unwrap()
                        .shutdown_timeout(0)
                        .start();

                        tx_server.send(server).unwrap();
                        sys.run().unwrap();
                    });
                }

                self.server = Some(
                    rx_server
                        .recv()
                        .context("receiving server from other thread")?,
                );

                eprintln!(
                    "[CallbackServer::spawn] started server on {}",
                    &self.bind_addr
                );

                Ok(())
            }

            async fn index(
                state: web::Data<Mutex<Sender<CallbackValues>>>,
                req: web::HttpRequest,
            ) -> impl Responder {
                let responder = || -> Fallible<_> {
                    eprintln!(
                        "[CallbackServer::index] processing incoming request on {}: {:#?}",
                        &req.headers()
                            .get("host")
                            .ok_or_else(|| failure::err_msg(
                                "could not find host in request headers"
                            ))?
                            .to_str()?,
                        &req,
                    );

                    let query_string = req.query_string().to_string();

                    let callback_values = actix_web::web::Query::<
                        std::collections::HashMap<String, String>,
                    >::from_query(&query_string)
                    .map_err(|e| failure::err_msg(e.to_string()))?
                    .into_inner();

                    state
                        .lock()
                        .map_err(|e| failure::err_msg(format!("could not acquire lock: {}", e)))?
                        .send(callback_values)?;

                    Ok("Ok"
                        .to_string()
                        .with_status(actix_web::http::StatusCode::OK))
                };

                match responder() {
                    Ok(ok) => ok,
                    Err(e) => e
                        .to_string()
                        .with_status(actix_web::http::StatusCode::BAD_REQUEST),
                }
            }
        }

        pub(crate) type CallbackValues = HashMap<String, String>;

        pub(crate) struct LoginChannels {
            pub(crate) authorize_url_sender: Sender<url::Url>,
            pub(crate) authorize_url_receiver: Receiver<url::Url>,

            pub(crate) callback_values_sender: Sender<CallbackValues>,
            pub(crate) callback_values_receiver: Receiver<CallbackValues>,
        }

        impl Default for LoginChannels {
            fn default() -> Self {
                use std::sync::mpsc::channel;
                let callback_url_channel = channel::<url::Url>();
                let callback_values_channel = channel::<CallbackValues>();

                LoginChannels {
                    authorize_url_sender: callback_url_channel.0,
                    authorize_url_receiver: callback_url_channel.1,

                    callback_values_sender: callback_values_channel.0,
                    callback_values_receiver: callback_values_channel.1,
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        #[cfg(feature = "test-net")]
        fn login_to_solid_community() -> Result<()> {
            let provider_url = "https://solid.community".to_string();
            let scopes = vec!["profile".to_string(), "email".to_string()];
            let bind_addr = "127.0.0.1:36666".to_string();

            let login_channels = callback_server::LoginChannels::default();

            let mut callback_server = callback_server::CallbackServer::try_new(
                bind_addr,
                login_channels.callback_values_sender,
            )?;
            callback_server.spawn()?;

            let relyingparty = {
                let authorize_url_sender = login_channels.authorize_url_sender;
                let callback_values_receiver = login_channels.callback_values_receiver;

                std::thread::spawn(move || -> Fallible<_> {
                    // TODO: ensure we're not already authorized

                    let _ = Client::login(LoginOptions {
                        provider_url,
                        scopes,
                        callback_url: callback_server.url().clone(),
                        authorize_url_sender,
                        callback_values_receiver,
                    })?;

                    // TODO: verify we're actually authorized

                    Ok(())
                })
            };

            let frontend = {
                let authorize_url_receiver = login_channels.authorize_url_receiver;

                std::thread::spawn(move || -> Fallible<_> {
                    let authorize_url = authorize_url_receiver.recv().unwrap();

                    automate_login(authorize_url)
                })
            };

            let _ = frontend.join().unwrap();
            let _ = relyingparty.join().unwrap();

            Ok(())
        }

        /// log in and authorize the request
        #[cfg(feature = "test-net")]
        fn automate_login(authorize_url: url::Url) -> Fallible<()> {
            eprintln!("TEST] got authorize url {}", authorize_url);

            let query_pairs = authorize_url
                .query_pairs()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<HashMap<String, String>>();

            let base_url = format!(
                "{}://{}",
                authorize_url.scheme(),
                authorize_url.host_str().unwrap()
            );

            // TODO: use a macro for this
            let scope = query_pairs.get("scope").unwrap();
            let client_id = query_pairs.get("client_id").unwrap();
            let nonce = query_pairs.get("nonce").unwrap();
            let redirect_uri = query_pairs.get("redirect_uri").unwrap();
            let response_type = query_pairs.get("response_type").unwrap();
            let state = query_pairs.get("state").unwrap();

            let http_client: reqwest::blocking::Client = reqwest::blocking::ClientBuilder::new()
                .cookie_store(true)
                .timeout(std::time::Duration::from_secs(5))
                // .redirect(reqwest::RedirectPolicy::none())
                .redirect(reqwest::RedirectPolicy::limited(10))
                .build()?;

            // GET to authorize endpoint
            let authorize_response = http_client.get(authorize_url.as_str()).send()?;
            assert_eq!(
                authorize_response.status(),
                reqwest::StatusCode::OK,
                "response: {:#?}",
                authorize_response
            );

            // POST to /password
            let password_response = http_client
                .post(&format!("{}/login/password", base_url))
                .form(&[
                    // POST
                    // curl 'https://solid.community/login/password' --data '
                    // username=user
                    ("username", &std::env::var("SOLID_USERNAME")?),
                    // &password=1243
                    ("password", &std::env::var("SOLID_PASSWORD")?),
                    // &response_type=code
                    ("response_type", response_type),
                    // &scope=openid+profile+email
                    ("scope", scope),
                    // &client_id=c6058f0d487151d7672373ace012c6b1
                    ("client_id", client_id),
                    // &state=EPnM_4kOajd1AP0jsdC7GA&nonce=ytGeLk9GIU9BAMpk7ws7NA
                    ("state", state),
                    // &redirect_uri=http%3A%2F%2F127.0.0.1%3A36667%2F
                    ("redirect_uri", redirect_uri),
                    // &nonce=ytGeLk9GIU9BAMpk7ws7NA&request='
                    ("nonce", nonce),
                    // &request=
                    // &display=
                ])
                .send()?;

            assert_eq!(
                password_response.status(),
                reqwest::StatusCode::OK,
                "response: {:#?}",
                password_response
            );

            // POST to /share
            let sharing_response = http_client
                .post(&format!("{}/sharing", base_url))
                .form(&[
                    // POST
                    // curl 'https://solid.community/sharing' --data '
                    // access_mode=Read
                    ("access_mode", "Read"),
                    // &consent=true
                    ("consent", "true"),
                    // &response_type=code
                    ("response_type", response_type),
                    // &display=
                    // &scope=openid+profile+email
                    ("scope", scope),
                    // &client_id=c6058f0d487151d7672373ace012c6b1
                    ("client_id", client_id),
                    // &redirect_uri=http%3A%2F%2F127.0.0.1%3A36667%2F
                    ("redirect_uri", redirect_uri),
                    // &nonce=ytGeLk9GIU9BAMpk7ws7NA&request='
                    ("nonce", nonce),
                    // &state=EPnM_4kOajd1AP0jsdC7GA
                    ("state", state),
                ])
                .send()?;
            assert_eq!(
                sharing_response.status(),
                reqwest::StatusCode::OK,
                "response: {:#?}",
                sharing_response
            );

            Ok(())
        }
    }
}
