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