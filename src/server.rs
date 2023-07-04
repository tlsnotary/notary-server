use eyre::{ensure, eyre, Result};
use futures_util::future::poll_fn;
use p256::{
    ecdsa::{Signature, SigningKey},
    pkcs8::DecodePrivateKey,
};
use rustls::{Certificate, PrivateKey, ServerConfig};
use std::{
    fs::File as StdFile,
    io::BufReader,
    net::{IpAddr, SocketAddr},
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
use tracing::{debug, error, info};

use crate::{
    config::{NotaryServerProperties, NotarySignatureProperties, TLSSignatureProperties},
    error::NotaryServerError,
};

/// Start a TLS-secured TCP server to accept notarization request
#[tracing::instrument(skip(config))]
pub async fn run_tcp_server(config: &NotaryServerProperties) -> Result<(), NotaryServerError> {
    // Load the private key and cert needed for TLS connection from fixture folder — can be swapped out when we stop using static self signed cert
    let (tls_private_key, tls_certificates) = load_tls_key_and_cert(&config.tls_signature).await?;
    // Load the private key for notarized transcript signing from fixture folder — can be swapped out when we use proper ephemeral signing key
    let notary_signing_key = load_notary_signing_key(&config.notary_signature).await?;

    // Build a TCP listener with TLS enabled
    let tls_config = Arc::new(
        ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(tls_certificates, tls_private_key)
            .map_err(|err| eyre!("Failed to instantiate notary server tls config: {err}"))?,
    );

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

    info!(
        "Listening for TLS-secured TCP traffic at {}",
        notary_address
    );

    loop {
        // Poll for any incoming connection constantly
        let (stream, prover_address) = match poll_fn(|cx| listener.poll_accept(cx)).await {
            Ok(connection) => connection,
            Err(err) => {
                error!("{}", NotaryServerError::Connection(err.to_string()));
                continue;
            }
        };
        debug!(?prover_address, "Received a prover's TCP connection");

        let acceptor = acceptor.clone();
        let notary_signing_key = notary_signing_key.clone();

        // Spawn a new async task to handle the new connection
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(stream) => {
                    info!(
                        ?prover_address,
                        "Accepted prover's TLS-secured TCP connection",
                    );
                    match notary_service(stream, &prover_address.to_string(), &notary_signing_key)
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
                        "{}",
                        NotaryServerError::Connection(err.to_string())
                    );
                }
            }
        });
    }
}

/// Run the notarization
#[tracing::instrument(skip(socket, signing_key))]
async fn notary_service<T: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    socket: T,
    prover_address: &str,
    signing_key: &SigningKey,
) -> Result<(), NotaryServerError> {
    debug!("Starting notarization...");

    // Use the prover address as the notarization session id as it is unique for each prover
    let config = NotaryConfig::builder().id(prover_address).build()?;
    let (notary, notary_fut) = bind_notary(config, socket.compat())?;

    // Spawn a new async task to run the background process
    tokio::spawn(notary_fut);

    notary.notarize::<Signature>(signing_key).await?;

    debug!("Notarization completed successfully!");
    Ok(())
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
async fn read_pem_file(file_path: &str) -> Result<BufReader<StdFile>> {
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

    use futures::AsyncWriteExt;
    use hyper::{body::to_bytes, Body, Request, StatusCode};
    use rustls::{ClientConfig, RootCertStore};
    use std::time::Duration;
    use tls_server_fixture::{bind_test_server, CA_CERT_DER, SERVER_DOMAIN};
    use tlsn_prover::{bind_prover, ProverConfig};
    use tokio_rustls::TlsConnector;
    use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

    use crate::config::{NotaryServerProperties, ServerProperties, TracingProperties};

    const NOTARY_CA_CERT_PATH: &str = "./src/fixture/tls/rootCA.crt";

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

    #[tokio::test]
    async fn test_notarization() {
        let notary_config = NotaryServerProperties {
            server: ServerProperties {
                name: "tlsnotaryserver.io".to_string(),
                domain: "127.0.0.1".to_string(),
                port: 7047,
            },
            tls_signature: TLSSignatureProperties {
                private_key_pem_path: "./src/fixture/tls/notary.key".to_string(),
                certificate_pem_path: "./src/fixture/tls/notary.crt".to_string(),
            },
            notary_signature: NotarySignatureProperties {
                private_key_pem_path: "./src/fixture/notary/notary.key".to_string(),
            },
            tracing: TracingProperties {
                default_level: "DEBUG".to_string(),
            },
        };

        tracing_subscriber::fmt::init();

        let config = notary_config.clone();

        // Run the the notary server
        tokio::spawn(async move {
            run_tcp_server(&config).await.unwrap();
        });

        // Sleep for a while to allow notary server to finish set up and start listening
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Run the prover
        run_prover(&notary_config).await;
    }

    #[tracing::instrument(skip(notary_config))]
    async fn run_prover(notary_config: &NotaryServerProperties) {
        // Connect to the Notary via TLS-TCP
        let mut certificate_file_reader = read_pem_file(NOTARY_CA_CERT_PATH).await.unwrap();
        let mut certificates: Vec<Certificate> =
            rustls_pemfile::certs(&mut certificate_file_reader)
                .unwrap()
                .into_iter()
                .map(Certificate)
                .collect();
        let certificate = certificates.remove(0);

        let mut root_store = RootCertStore::empty();
        root_store.add(&certificate).unwrap();

        let client_notary_config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let notary_connector = TlsConnector::from(Arc::new(client_notary_config));

        let notary_socket = tokio::net::TcpStream::connect(SocketAddr::new(
            IpAddr::V4(notary_config.server.domain.parse().unwrap()),
            notary_config.server.port,
        ))
        .await
        .unwrap();

        let prover_address = notary_socket.local_addr().unwrap().to_string();
        let notary_tls_socket = notary_connector
            .connect(
                notary_config.server.name.as_str().try_into().unwrap(),
                notary_socket,
            )
            .await
            .unwrap();

        // Connect to the Server
        let (client_socket, server_socket) = tokio::io::duplex(2 << 16);
        let server_task = tokio::spawn(bind_test_server(server_socket.compat()));

        let mut root_store = tls_core::anchors::RootCertStore::empty();
        root_store
            .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
            .unwrap();

        // Basic default prover config — use local address as the notarization session id
        let prover_config = ProverConfig::builder()
            .id(prover_address)
            .server_dns(SERVER_DOMAIN)
            .root_cert_store(root_store)
            .build()
            .unwrap();

        // Bind the Prover to the sockets
        let (tls_connection, prover_fut, mux_fut) = bind_prover(
            prover_config,
            client_socket.compat(),
            notary_tls_socket.compat(),
        )
        .await
        .unwrap();

        // Spawn the Prover and Mux tasks to be run concurrently
        tokio::spawn(mux_fut);
        let prover_task = tokio::spawn(prover_fut);

        let (mut request_sender, connection) =
            hyper::client::conn::handshake(tls_connection.compat())
                .await
                .unwrap();

        let connection_task = tokio::spawn(connection.without_shutdown());

        let request = Request::builder()
            .uri(format!("https://{}/echo", SERVER_DOMAIN))
            .header("Host", SERVER_DOMAIN)
            .header("Connection", "close")
            .method("POST")
            .body(Body::from("echo"))
            .unwrap();

        debug!("Sending request to server: {:?}", request);

        let response = request_sender.send_request(request).await.unwrap();

        assert!(response.status() == StatusCode::OK);

        debug!(
            "Received response from server: {:?}",
            String::from_utf8_lossy(&to_bytes(response.into_body()).await.unwrap())
        );

        let mut server_tls_conn = server_task.await.unwrap().unwrap();

        // Make sure the server closes cleanly (sends close notify)
        server_tls_conn.close().await.unwrap();

        let mut client_socket = connection_task.await.unwrap().unwrap().io.into_inner();

        client_socket.close().await.unwrap();

        let mut prover = prover_task.await.unwrap().unwrap();

        let sent_len = prover.sent_transcript().data().len();
        let recv_len = prover.recv_transcript().data().len();

        prover.add_commitment_sent(0..sent_len as u32).unwrap();
        prover.add_commitment_recv(0..recv_len as u32).unwrap();

        _ = prover.finalize().await.unwrap();
    }
}
