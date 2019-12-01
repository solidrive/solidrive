/// This module implements the WebID-OIDC protocol
pub mod webid_oidc {
    use failure::{bail, Fallible, ResultExt};
    use openidconnect::core::{CoreClientRegistrationRequest, CoreProviderMetadata};
    use openidconnect::registration::EmptyAdditionalClientMetadata;
    use openidconnect::reqwest::http_client;
    use openidconnect::{AccessToken, ClientId, ClientSecret, IssuerUrl, RegistrationUrl};

    type Result<T> = Fallible<T>;

    /// Request the OpenID discovery document from the given URL
    fn discover(provider_url: String) -> Result<CoreProviderMetadata> {
        Ok(
            CoreProviderMetadata::discover(&IssuerUrl::new(provider_url)?, http_client)
                .context("provider metadata discovery")?,
        )
    }

    /// Register with the given provider
    pub fn register(provider_url: String, redirect_urls: Vec<String>) -> Result<(String, String)> {
        let registration = CoreClientRegistrationRequest::new(
            redirect_urls
                .into_iter()
                .map(|redirect_url| openidconnect::RedirectUrl::new(redirect_url).unwrap())
                .collect(),
            EmptyAdditionalClientMetadata::default(),
        );

        // TODO: think about getting this via the arguments instead of discovering
        let provider_metadata = discover(provider_url.clone()).context("discover for register")?;

        let registration_url = provider_metadata
            .registration_endpoint()
            .unwrap()
            .to_string();

        let response = registration
            .register(
                &RegistrationUrl::new(registration_url.clone()).context("new registration url")?,
                http_client,
            )
            .context(format!("registration at {}", &registration_url))?;

        Ok((
            response.client_id().as_str().to_string(),
            response.client_secret().unwrap().secret().to_string(),
        ))
    }

    /// These paramters are passed to the `login` function
    pub struct LoginOptions {
        pub(crate) issuer_url: String,
        pub(crate) callback_uri: String,
        pub(crate) client_id: String,
        pub(crate) client_secret: String,
        pub(crate) rx_query_params: std::sync::mpsc::Receiver<String>,
        pub(crate) scopes: Vec<String>,
    }

    /// Perform a [WebID-OIDC][spec] authentication code flow and return the access token and the WebID URI
    ///
    /// An example workflow [is described in the web-oidc-spec repository][example-workflow].
    ///
    /// [spec]: https://github.com/solid/webid-oidc-spec/blob/0e6da67a624a4d09ab85e28bafe85da33f860a61/README.md
    /// [example-workflow]: https://github.com/solid/webid-oidc-spec/blob/master/example-workflow.md
    pub fn login(options: LoginOptions) -> Result<AccessToken> {
        use openidconnect::core::{CoreClient, CoreResponseType};
        use openidconnect::{
            AccessTokenHash, AuthenticationFlow, AuthorizationCode, CsrfToken, Nonce,
            PkceCodeChallenge, RedirectUrl, Scope,
        };
        use openidconnect::{OAuth2TokenResponse, TokenResponse};

        let provider_metadata = discover(options.issuer_url).context("discover for login")?;

        // Create an OpenID Connect client by specifying the client ID, client secret, authorization URL
        // and token URL.
        let client = CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(options.client_id),
            Some(ClientSecret::new(options.client_secret)),
        )
        // Set the URL the user will be redirected to after the authorization process.
        .set_redirect_uri(RedirectUrl::new(options.callback_uri).context("setting redirect url")?);

        // Generate a PKCE challenge.
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        // Generate the full authorization URL.
        let (auth_url, csrf_token, nonce) = {
            let mut authorizan_request = client
                .authorize_url(
                    AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
                    CsrfToken::new_random,
                    // TODO: figure out what to do with the nonce
                    Nonce::new_random,
                )
                .set_pkce_challenge(pkce_challenge);

            // Set the desired scopes.
            for scope in options.scopes {
                authorizan_request = authorizan_request.add_scope(Scope::new(scope.to_string()));
            }

            authorizan_request.url()
        };

        // This is the URL you should redirect the user to, in order to trigger the authorization
        // process.
        println!("Please browse to: {}", auth_url);

        // Once the user has authorized the request, we'll receive the query parameters from the background server
        let query_params = options
            .rx_query_params
            .recv()
            .context("receiving query_params")?;
        println!("received query_string");

        let params =
            actix_web::web::Query::<std::collections::HashMap<String, String>>::from_query(
                &query_params,
            )
            .unwrap()
            .into_inner();

        // For security reasons, verify that the `state` parameter returned by the server matches `csrf_state`
        match params.get("state") {
            Some(state) => {
                let token = CsrfToken::new(state.to_string());
                if token.secret() != csrf_token.secret() {
                    bail!("received state {}, expected: {:?}", state, &csrf_token);
                }
            }
            None => bail!("no state in query parameters: {:?}", params),
        };

        // Get the code from the parameters
        let code = match params.get("code") {
            Some(code) => code.to_string(),
            None => bail!("no code in query parameters: {:?}", params),
        };

        // Now you can exchange it for an access token and ID token.
        let token_response = client
            .exchange_code(AuthorizationCode::new(code))
            // Set the PKCE code verifier.
            .set_pkce_verifier(pkce_verifier)
            .request(http_client)
            .context("exchange code for token")?;

        // Extract the ID token claims after verifying its authenticity and nonce.
        let id_token = token_response
            .id_token()
            .unwrap()
            .claims(&client.id_token_verifier(), &nonce)?;

        // Verify the access token hash to ensure that the access token hasn't been substituted for
        // another user's.
        if let Some(expected_access_token_hash) = id_token.access_token_hash() {
            let actual_access_token_hash = AccessTokenHash::from_token(
                token_response.access_token(),
                &token_response.id_token().unwrap().signing_alg()?,
            )?;
            if actual_access_token_hash != *expected_access_token_hash {
                return Err(failure::Error::from_boxed_compat(
                    "Invalid access token".into(),
                ));
            }
        }

        // The authenticated user's identity is now available. See the IdTokenClaims struct for a
        // complete listing of the available claims.
        println!(
            "User {} with e-mail address {} has authenticated successfully",
            id_token.subject().as_str(),
            id_token
                .email()
                .map(|email| email.as_str())
                .unwrap_or("<not provided>"),
        );

        // TODO: Derive WebID URI from IT Token as described at
        // https://github.com/solid/webid-oidc-spec/blob/0e6da67a624a4d09ab85e28bafe85da33f860a61/README.md#deriving-webid-uri-from-id-token

        let access_token = token_response.access_token();
        let _token_type = token_response.token_type();
        let _scopes = token_response.scopes();
        let _refresh_token = token_response.refresh_token();
        let _expires_in = token_response.expires_in();
        // See the OAuth2TokenResponse trait for a listing of other available fields such as
        // access_token() and refresh_token().

        Ok(access_token.clone())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn spawn_callback_server(bind_addr: String) -> Fallible<std::sync::mpsc::Receiver<String>> {
            // spawn a callback server for this

            use actix_web::{web, App, HttpServer, Responder};

            let (tx_server, rx_server) = std::sync::mpsc::channel();
            let (tx_request, rx_request) = std::sync::mpsc::channel::<String>();

            struct AppData(pub std::sync::mpsc::Sender<String>);
            let app_data = web::Data::new(std::sync::Mutex::new(AppData(tx_request)));

            async fn index(
                state: web::Data<std::sync::Mutex<AppData>>,
                req: web::HttpRequest,
            ) -> impl Responder {
                println!(
                    "processing incoming request on {}",
                    &req.headers().get("host").unwrap().to_str().unwrap()
                );

                let query_string = req.query_string().to_string();
                state.lock().unwrap().0.send(query_string).unwrap();

                "Ok".to_string()
            }

            std::thread::spawn(move || {
                let sys = actix_rt::System::new("callback-server");

                let server = HttpServer::new(move || {
                    App::new().service(web::resource("/").to(index).register_data(app_data.clone()))
                })
                .bind(&bind_addr)
                .context(format!("binding server to {}", &bind_addr))
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

        #[test]
        #[cfg(feature = "test-net")]
        #[cfg(feature = "test-interactive")]
        fn login_to_solid_community() -> Result<()> {
            let bind_addr = String::from("127.0.0.1:36666");

            let callback_uri = format!("http://{}", bind_addr);
            let provider_url = "https://solid.community".to_string();
            let issuer_url = "https://solid.community".to_string();
            let scopes = vec!["read".to_string(), "write".to_string()];

            let rx_query_params = spawn_callback_server(bind_addr)?;

            let (client_id, client_secret) =
                register(provider_url.clone(), vec![callback_uri.clone()])
                    .context("registration call in test")?;

            let login_options = LoginOptions {
                issuer_url,
                callback_uri,
                client_id,
                client_secret,
                rx_query_params,
                scopes,
            };

            let _ = login(login_options).context("test login").unwrap();

            Ok(())
        }
    }
}
