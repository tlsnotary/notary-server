[![CI](https://github.com/tlsnotary/notary-server/actions/workflows/rust.yml/badge.svg)](https://github.com/tlsnotary/notary-server/actions)


# notary-server

An implementation of the notary server in Rust.

## ⚠️ Notice

This project is currently under active development and should not be used in production. Expect bugs and regular major breaking changes.

---
## Running the server
1. Configure the server setting in this [file](./src/config/config.yaml) — refer [here](./src/config.rs) for more information on the definition of the setting parameters.
2. Start the server by running following in a terminal at the top level of this project.
```bash
cargo run
```
3. To use a config file from a different location, run the following command to override the default config file location.
```bash
cargo run -- --config-file <path-to-new-config-file>
```

---
## API
All APIs are TLS-protected, hence please use `https://` or `wss://`.
### HTTP APIs
Defined in the [OpenAPI specification](./openapi.yaml).

### WebSocket APIs
#### /ws-notarize
##### Description
To perform notarization using the session id (unique id returned upon calling the `/notarize` endpoint successfully) submitted as a custom header.

##### Custom Header
`X-Session-Id`

##### Custom Header Type
String

---
## Architecture
### Objective
The main objective of a notary server is to perform notarization together with a prover. In this case, the prover can either be
1. TCP client — which has access and control over the transport layer, i.e. TCP
2. WebSocket client — which has no access over TCP and instead uses WebSocket for notarization

### Design Choices
#### Web Framework
Axum is chosen as the framework to serve HTTP and WebSocket requests from the prover clients due to its rich and well supported features, e.g. native integration with Tokio/Hyper/Tower, customizable middleware, ability to support lower level integration of TLS ([example](https://github.com/tokio-rs/axum/blob/main/examples/low-level-rustls/src/main.rs)). To simplify the notary server setup, a single Axum router is used to support both HTTP and WebSocket connections, i.e. all requests can be made to the same port of the notary server.

#### Notarization Configuration
To perform notarization, some parameters need to be configured by the prover and notary server (more details in the [OpenAPI specification](./openapi.yaml)), i.e.
- maximum transcript size
- unique session id

To streamline this process, a single HTTP endpoint (`/notarize`) is used by both TCP and WebSocket clients. The only difference being, for TCP client, the notarization process will be kickstarted at the end of this configuration, whereas WebSocket client will need to establish a separate WebSocket connection to a different endpoint (`/ws-notarize`).

#### WebSocket
Axum's internal implementation of WebSocket uses [tokio_tungstenite](https://docs.rs/tokio-tungstenite/latest/tokio_tungstenite/), which provides a WebSocket struct that doesn't implement [AsyncRead](https://docs.rs/futures/latest/futures/io/trait.AsyncRead.html) and [AsyncWrite](https://docs.rs/futures/latest/futures/io/trait.AsyncWrite.html). Both these traits are required by TLSN core libraries for prover and notary. To overcome this, a [slight modification](./src/axum_websocket.rs) of Axum's implementation of WebSocket is used, where [async_tungstenite](https://docs.rs/async-tungstenite/latest/async_tungstenite/) is used instead so that [ws_stream_tungstenite](https://docs.rs/ws_stream_tungstenite/latest/ws_stream_tungstenite/index.html) can be used to wrap on top of the WebSocket struct to get AsyncRead and AsyncWrite implemented.
