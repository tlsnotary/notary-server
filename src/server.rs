use async_trait::async_trait;
use axum::{
    extract::FromRequestParts,
    extract::State,
    http::{header, Request, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use eyre::{ensure, eyre, Result};
use futures_util::future::poll_fn;
use http::request::Parts;
use hyper::{
    server::{
        accept::Accept,
        conn::{AddrIncoming, Http},
    },
    upgrade::OnUpgrade,
};
use p256::{
    ecdsa::{Signature, SigningKey},
    pkcs8::DecodePrivateKey,
};
use rustls::{Certificate, PrivateKey, ServerConfig};
use std::{
    fs::File as StdFile,
    io::BufReader,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
};
use tlsn_notary::{bind_notary, NotaryConfig};
use tokio::{
    fs::File,
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
};
use tokio_rustls::TlsAcceptor;
use tokio_util::compat::TokioAsyncReadCompatExt;
use tower::MakeService;
use tracing::{debug, error, info};
use uuid::Uuid;
use ws_stream_tungstenite::WsStream;

use crate::{
    config::{NotaryServerProperties, NotarySignatureProperties, TLSSignatureProperties},
    domain::notary::NotarizationResponse,
    error::NotaryServerError,
    websocket::{WebSocket, WebSocketUpgrade},
};

struct RawTcpExtractor {
    pub on_upgrade: OnUpgrade,
}

#[async_trait]
impl<S> FromRequestParts<S> for RawTcpExtractor
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let on_upgrade = parts.extensions.remove::<OnUpgrade>().ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Something wrong when extracting raw TCP".to_string(),
        ))?;

        Ok(Self { on_upgrade })
    }
}

/// Start a TLS-secured TCP server to accept notarization request
#[tracing::instrument(skip(config))]
pub async fn run_server(config: &NotaryServerProperties) -> Result<(), NotaryServerError> {
    // Load the private key and cert needed for TLS connection from fixture folder — can be swapped out when we stop using static self signed cert
    let (tls_private_key, tls_certificates) = load_tls_key_and_cert(&config.tls_signature).await?;
    // Load the private key for notarized transcript signing from fixture folder — can be swapped out when we use proper ephemeral signing key
    let notary_signing_key = load_notary_signing_key(&config.notary_signature).await?;

    // Build a TCP listener with TLS enabled
    let mut server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(tls_certificates, tls_private_key)
        .map_err(|err| eyre!("Failed to instantiate notary server tls config: {err}"))?;

    // Set the http protocols we support to upgrade to
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tls_config = Arc::new(server_config);

    let notary_address = SocketAddr::new(
        IpAddr::V4(config.server.domain.parse().map_err(|err| {
            eyre!("Failed to parse notary host address from server config: {err}")
        })?),
        config.server.port,
    );

    let acceptor = TlsAcceptor::from(tls_config);
    let listener = TcpListener::bind(notary_address)
        .await
        .map_err(|err| eyre!("Failed to bind server address to tcp listener: {err}"))?;
    let mut listener = AddrIncoming::from_listener(listener)
        .map_err(|err| eyre!("Failed to build hyper tcp listener: {err}"))?;

    info!(
        "Listening for TLS-secured TCP traffic at {}",
        notary_address
    );

    let protocol = Arc::new(Http::new());
    let router = Router::new()
        .route(
            "/healthcheck",
            get(|| async move { (StatusCode::OK, "Ok").into_response() }),
        )
        .route("/notarize", post(configuration_service))
        .route("/ws-notarize", get(upgrade_websocket))
        .with_state(notary_signing_key);
    let mut app = router.into_make_service();

    loop {
        // Poll for any incoming connection constantly, ensure that all operations inside are infallible to prevent bringing down the server
        let (prover_address, stream) =
            match poll_fn(|cx| Pin::new(&mut listener).poll_accept(cx)).await {
                Some(Ok(connection)) => (connection.remote_addr(), connection),
                _ => {
                    error!("{}", NotaryServerError::Connection("".to_string()));
                    continue;
                }
            };
        debug!(?prover_address, "Received a prover's TCP connection");

        let acceptor = acceptor.clone();
        let protocol = protocol.clone();
        let service = MakeService::<_, Request<hyper::Body>>::make_service(&mut app, &stream);

        // Spawn a new async task to handle the new connection
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(stream) => {
                    info!(
                        ?prover_address,
                        "Accepted prover's TLS-secured TCP connection",
                    );

                    let _ = protocol
                        // Can unwrap because it's infallible
                        .serve_connection(stream, service.await.unwrap())
                        .with_upgrades()
                        .await;
                }
                Err(err) => {
                    error!(
                        ?prover_address,
                        "{}",
                        NotaryServerError::Connection(err.to_string())
                    );
                }
            }
        });
    }
}

async fn configuration_service(
    tcp_extractor: RawTcpExtractor,
    State(notary_signing_key): State<SigningKey>,
) -> Response {
    debug!("Received request for configuration");

    let prover_session_id = Uuid::new_v4().to_string();
    let notary_session_id = prover_session_id.clone();

    tokio::spawn(async move {
        let stream = match tcp_extractor.on_upgrade.await {
            Ok(upgraded) => upgraded,
            Err(err) => {
                error!("Something wrong with on_upgrade: {:?}", err);
                return;
            }
        };
        debug!("Successfully extracted tcp connection.");
        match notary_service(stream, &notary_session_id, &notary_signing_key).await {
            Ok(_) => {
                info!("Successful notarization for raw tcp!");
            }
            Err(err) => {
                error!("Failed notarization for raw tcp: {err}");
            }
        }
    });
    (
        StatusCode::OK,
        // Need to send close to signal client to close the http connection so that client will proceed to start notarization
        [(header::CONNECTION, "close")],
        Json(NotarizationResponse {
            session_id: prover_session_id,
        }),
    )
        .into_response()
}

async fn upgrade_websocket(
    ws: WebSocketUpgrade,
    State(notary_signing_key): State<SigningKey>,
) -> Response {
    debug!("Received websocket request: {:?}", ws);
    ws.on_upgrade(|socket| websocket_service(socket, notary_signing_key))
}

async fn websocket_service(socket: WebSocket, notary_signing_key: SigningKey) {
    debug!("Upgraded to websocket connection");
    let stream = WsStream::new(socket.into_inner());
    match notary_service(stream, "test-websocket", &notary_signing_key).await {
        Ok(_) => {
            info!("Successful notarization for websocket!");
        }
        Err(err) => {
            error!("Failed notarization for websocket: {err}");
        }
    }
}

/// Run the notarization
async fn notary_service<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    socket: T,
    session_id: &str,
    signing_key: &SigningKey,
) -> Result<(), NotaryServerError> {
    debug!(?session_id, "Starting notarization...");

    let config = NotaryConfig::builder().id(session_id).build()?;
    let (notary, notary_fut) = bind_notary(config, socket.compat())?;

    // Run the notary and background processes concurrently
    tokio::try_join!(notary_fut, notary.notarize::<Signature>(signing_key),).map(|_| Ok(()))?
}

/// Temporary function to load notary signing key from static file
async fn load_notary_signing_key(config: &NotarySignatureProperties) -> Result<SigningKey> {
    debug!("Loading notary server's signing key");

    let notary_signing_key = SigningKey::read_pkcs8_pem_file(&config.private_key_pem_path)
        .map_err(|err| eyre!("Failed to load notary signing key for notarization: {err}"))?;

    debug!("Successfully loaded notary server's signing key!");
    Ok(notary_signing_key)
}

/// Read a PEM-formatted file and return its buffer reader
pub async fn read_pem_file(file_path: &str) -> Result<BufReader<StdFile>> {
    let key_file = File::open(file_path).await?.into_std().await;
    Ok(BufReader::new(key_file))
}

/// Load notary tls private key and cert from static files
async fn load_tls_key_and_cert(
    config: &TLSSignatureProperties,
) -> Result<(PrivateKey, Vec<Certificate>)> {
    debug!("Loading notary server's tls private key and certificate");

    let mut private_key_file_reader = read_pem_file(&config.private_key_pem_path).await?;
    let mut private_keys = rustls_pemfile::pkcs8_private_keys(&mut private_key_file_reader)?;
    ensure!(
        private_keys.len() == 1,
        "More than 1 key found in the tls private key pem file"
    );
    let private_key = PrivateKey(private_keys.remove(0));

    let mut certificate_file_reader = read_pem_file(&config.certificate_pem_path).await?;
    let certificates = rustls_pemfile::certs(&mut certificate_file_reader)?
        .into_iter()
        .map(Certificate)
        .collect();

    debug!("Successfully loaded notary server's tls private key and certificate!");
    Ok((private_key, certificates))
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn test_load_notary_key_and_cert() {
        let config = TLSSignatureProperties {
            private_key_pem_path: "./src/fixture/tls/notary.key".to_string(),
            certificate_pem_path: "./src/fixture/tls/notary.crt".to_string(),
        };
        let result: Result<(PrivateKey, Vec<Certificate>)> = load_tls_key_and_cert(&config).await;
        assert!(result.is_ok(), "Could not load tls private key and cert");
    }

    #[tokio::test]
    async fn test_load_notary_signing_key() {
        let config = NotarySignatureProperties {
            private_key_pem_path: "./src/fixture/notary/notary.key".to_string(),
        };
        let result: Result<SigningKey> = load_notary_signing_key(&config).await;
        assert!(result.is_ok(), "Could not load notary private key");
    }
}
