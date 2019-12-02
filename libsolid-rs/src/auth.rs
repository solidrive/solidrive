/// This module implements the WebID-OIDC protocol
pub mod webid_oidc {
    use failure::{bail, Fallible, ResultExt};
    use openidconnect::core::{
        CoreClient, CoreClientRegistrationRequest, CoreProviderMetadata, CoreResponseType,
    };
    use openidconnect::registration::EmptyAdditionalClientMetadata;
    use openidconnect::reqwest::http_client;
    use openidconnect::{
        AccessToken, AccessTokenHash, AuthenticationFlow, AuthorizationCode, ClientId,
        ClientSecret, CsrfToken, IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge,
        RegistrationUrl, Scope, TokenResponse,
    };

    use std::collections::{HashMap, HashSet};

    type Result<T> = Fallible<T>;

    pub type ProviderID = String;

    pub type ProviderMetadata = CoreProviderMetadata;

    pub struct Provider {
        id: ProviderID,
        metadata: ProviderMetadata,
    }

    pub struct RegistrationCredentials {
        client_id: String,
        client_secret: String,
    }

    pub struct Registration {
        provider: Provider,
        credentials: RegistrationCredentials,

        // TODO: verify if (and why) we need to store this
        redirect_url: String,
    }

    pub type WebID = String;

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
        registration: Registration,
        oidc_client: openidconnect::core::CoreClient,
        access_tokens: HashMap<WebID, AccessCredentials>,
    }

    impl Client {
        /// Initiates an interactive login to the given provider
        pub fn login(
            provider_url: ProviderID,
            scopes: Vec<String>,
            callback_bind_addr: String,
        ) -> Result<Self> {
            let provider_metadata = Self::discover(provider_url.clone())
                .context(format!("discover provider {}", &provider_url))?;

            let registration = {
                let redirect_url = format!("http://{}", callback_bind_addr);
                let registration_credentials = Self::register(&provider_metadata, &redirect_url)
                    .context(format!("registration with provider {}", &provider_url))?;

                Registration {
                    provider: Provider {
                        id: provider_url,
                        metadata: provider_metadata,
                    },
                    credentials: registration_credentials,
                    redirect_url,
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

            let query_params_rx_channel =
                Self::spawn_callback_server(callback_bind_addr.clone())
                    .context(format!("spawn callback server on {}", callback_bind_addr))?;

            let credentials = Self::authorize(
                &oidc_client,
                scopes.into_iter().map(Scope::new).collect(),
                |url| -> Fallible<_> {
                    println!("Please browse to: {}", url);

                    // Once the user has authorized the request, we'll receive the query parameters from the background server
                    let query_params = query_params_rx_channel.recv().context("receiving query_params")?;

                    println!("received query_string");

                    Ok(
                        actix_web::web::Query::<std::collections::HashMap<String, String>>::from_query(&query_params)
                        .map_err(|e|failure::err_msg(e.to_string()))?
                        .into_inner()
                    )
                }
            )
            .context("authorization")?;

            let access_tokens = vec![("TODO: some ressource id here".to_string(), credentials)]
                .into_iter()
                .collect::<HashMap<WebID, AccessCredentials>>();

            Ok(Client {
                registration,
                oidc_client,
                access_tokens,
            })
        }

        fn spawn_callback_server(bind_addr: String) -> Fallible<std::sync::mpsc::Receiver<String>> {
            use actix_web::{web, App, HttpServer, Responder};
            use std::sync::{mpsc, Mutex};

            let (tx_server, rx_server) = mpsc::channel();
            let (tx_request, rx_request) = mpsc::channel::<String>();

            struct AppData(pub mpsc::Sender<String>);
            let app_data = web::Data::new(Mutex::new(AppData(tx_request)));

            async fn index(
                state: web::Data<Mutex<AppData>>,
                req: web::HttpRequest,
            ) -> impl Responder {
                println!(
                    "processing incoming request on {}",
                    &req.headers()
                        .get("host")
                        // TODO: remove unwrap
                        .unwrap()
                        .to_str()
                        // TODO: remove unwrap
                        .unwrap()
                );

                let query_string = req.query_string().to_string();
                state
                    .lock()
                    // TODO: remove unwrap
                    .unwrap()
                    .0
                    .send(query_string)
                    // TODO: remove unwrap
                    .unwrap();

                "Ok".to_string()
            }

            std::thread::spawn(move || {
                let sys = actix_rt::System::new("callback-server");

                let server = HttpServer::new(move || {
                    App::new().service(web::resource("/").to(index).register_data(app_data.clone()))
                })
                .bind(&bind_addr)
                .context(format!("binding server to {}", &bind_addr))
                // TODO: remove unwrap
                .unwrap()
                .shutdown_timeout(0)
                .start();

                println!("started server");

                let _ = tx_server.send(server);
                let _ = sys.run();
            });

            let _ = rx_server.recv().context("receiving addr")?;
            println!("callback server spawned");

            Ok(rx_request)
        }

        fn discover(provider_url: ProviderID) -> Result<ProviderMetadata> {
            Ok(
                CoreProviderMetadata::discover(&IssuerUrl::new(provider_url)?, http_client)
                    .context("provider metadata discovery")?,
            )
        }

        fn register(
            provider_metadata: &CoreProviderMetadata,
            redirect_url: &str,
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
                    http_client,
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

        fn authorize<F>(
            oidc_client: &CoreClient,
            requested_scopes: HashSet<Scope>,
            auth_callback_values_fn: F,
        ) -> Result<AccessCredentials>
        where
            F: FnOnce(&url::Url) -> Fallible<HashMap<String, String>>,
        {
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

            // Pass the auth_url to the caller and wait for the callback values.
            let code = auth_callback_values_fn(auth_url)
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
                .request(http_client)
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
                        "requested scopes {:?} but was authorized is for {:?}",
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

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        #[cfg(feature = "test-net")]
        #[cfg(feature = "test-interactive")]
        fn interactive_login_to_solid_community() -> Result<()> {
            let callback_bind_addr = String::from("127.0.0.1:36666");

            let provider_url = "https://solid.community".to_string();
            let scopes = vec!["profile".to_string(), "email".to_string()];

            let _ = Client::login(provider_url, scopes, callback_bind_addr).unwrap();

            Ok(())
        }
    }
}
