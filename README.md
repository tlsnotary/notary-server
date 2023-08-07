[![CI](https://github.com/tlsnotary/notary-server/actions/workflows/rust.yml/badge.svg)](https://github.com/tlsnotary/notary-server/actions)


# notary-server

An implementation of the notary server in Rust.

## ⚠️ Notice

This project is currently under active development and should not be used in production. Expect bugs and regular major breaking changes.

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

## API
### HTTP APIs
Defined in the [OpenAPI specification](./openapi.yaml).

### WebSocket APIs
#### /ws-notarize
##### Description
To perform notarization using the session id (unique id returned upon calling the /notarize endpoint successfully) submitted as a custom header

##### Custom Header
X-Session-Id

##### Custom Header Type
String
