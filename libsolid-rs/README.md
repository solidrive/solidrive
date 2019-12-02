# libsolid-rs
This library aims to provide all client-side functionality for reading and writing linked data from and to a SOLID POD server.


## Features
_Note: It's early days :-)_

### Authentication
This library supports only [WebID-OIDC](webid-oidc) [(spec)][solid-webid-oidc].
There currently no plans to support WebID-TLS.

Implemented:
* Basic Oauth2 Client Registration
* Plain OIDC Discovery
* Plain OIDC Login

Next:
* See [issues with the _auth_ label](https://github.com/steveeJ/coegi/labels/auth)

### Data transfer
#### [Rest API](rest-api) [(spec)][solid-rest-api]
Planned

#### [Websocket API](websocket-api) [(spec)][solid-websocket-api]
Maybe

[solid-webid-oidc]: https://github.com/solid/webid-oidc-spec/blob/master/README.md
[solid-rest-api]: https://github.com/solid/solid-spec/blob/master/api-rest.md
[solid-websocket-api]: https://github.com/solid/solid-spec/blob/master/api-websockets.md

## Tests
To run all tests in the library it is currently recommended to use the following command:

```console
cargo test --jobs 1 --features test-net,test-interactive -- --nocapture
```

The reason why we only want to run 1 job at a time is the execution of the interactive tests.
These depend on the user reading and processing console output, which may be be out of order if multiple tests are run in parallel.
This is [intended to change in the future](https://github.com/steveeJ/coegi/issues/8).