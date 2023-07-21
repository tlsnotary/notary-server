use axum::{
    http::{Request, StatusCode, header},
    response::{IntoResponse, Json},
    routing::{get, post},
    Extension, Router,
};
use eyre::{ensure, eyre, Result};
use futures_util::future::poll_fn;
use hyper::server::{
    accept::Accept,
    conn::{AddrIncoming, Http, Parts},
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
    sync::mpsc::{self, Sender},
};
use tokio_rustls::TlsAcceptor;
use tokio_util::compat::TokioAsyncReadCompatExt;
use tower::MakeService;
use tracing::{debug, error, info};
use uuid::Uuid;

use crate::{
    config::{NotaryServerProperties, NotarySignatureProperties, TLSSignatureProperties},
    domain::notary::NotarizationResponse,
    error::NotaryServerError,
};

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
    let router = Router::<()>::new()
        .route("/healthcheck", get(|| async move { "Ok" }))
        .route(
            "/notarize",
            post(|tx: Extension<Sender<()>>| async move {
                if let Err(err) = tx.try_send(()) {
                    return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response();
                }
                debug!("Sent ping message to trigger notarization.");
                (
                    StatusCode::OK,
                    // Need to send close to signal client to close the http connection so that client will proceed to start notarization
                    [(header::CONNECTION, "close")],
                    Json(NotarizationResponse {
                        session_id: Uuid::new_v4().to_string(),
                    }),
                )
                .into_response()
            }),
        );

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
        let notary_signing_key = notary_signing_key.clone();

        let protocol = protocol.clone();
        // Establish a channel for handler to trigger notarization — this is mainly because we are
        // using the same port for all requests, e.g. notarization via raw TCP, WebSocket, and in order to
        // start notarization on raw TCP after talking HTTP, we can only claim back the TLS socket at the server thread level
        // instead of the handler level, hence the server thread needs to know when to notarize (if it's raw TCP) and
        // when not to notarize (when it's WebSocket)
        let (tx, mut rx) = mpsc::channel::<()>(100);
        let mut app = router.clone().layer(Extension(tx)).into_make_service();
        let service = MakeService::<_, Request<hyper::Body>>::make_service(&mut app, &stream);

        // Spawn a new async task to handle the new connection
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(stream) => {
                    info!(
                        ?prover_address,
                        "Accepted prover's TLS-secured TCP connection",
                    );

                    let connection_result = protocol
                        // Can unwrap because it's infallible
                        .serve_connection(stream, service.await.unwrap())
                        .without_shutdown()
                        .await;
                    // Only start notarization if we receive the triggering signal from the right handler
                    if rx.try_recv().is_ok() {
                        match connection_result {
                            Ok(Parts { io: stream, .. }) => {
                                debug!(
                                    ?prover_address,
                                    "Successfully downgrade http to tls stream for notarization."
                                );

                                match notary_service(
                                    stream,
                                    &prover_address.to_string(),
                                    &notary_signing_key,
                                )
                                .await
                                {
                                    Ok(_) => {
                                        info!(?prover_address, "Successful notarization!");
                                    }
                                    Err(err) => {
                                        error!(?prover_address, "Failed notarization: {err}");
                                    }
                                }
                            }
                            Err(err) => {
                                error!(
                                    ?prover_address,
                                    "Something wrong in the notarization http request: {err}"
                                );
                            }
                        }
                    }
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

/// Run the notarization
async fn notary_service<T: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    socket: T,
    prover_address: &str,
    signing_key: &SigningKey,
) -> Result<(), NotaryServerError> {
    debug!(?prover_address, "Starting notarization...");

    // Temporarily use the prover address as the notarization session id as it is unique for each prover
    let config = NotaryConfig::builder().id(prover_address).build()?;
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
