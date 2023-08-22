use futures::AsyncWriteExt;
use hyper::{body::to_bytes, Body, Request, StatusCode};
use rustls::{Certificate, ClientConfig, RootCertStore};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tls_server_fixture::{bind_test_server_hyper, CA_CERT_DER, SERVER_DOMAIN};
use tlsn_prover::{bind_prover, ProverConfig};
use tokio_rustls::TlsConnector;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::debug;

use notary_server::{
    read_pem_file, run_tcp_server, NotaryServerProperties, NotarySignatureProperties,
    ServerProperties, TLSSignatureProperties, TracingProperties,
};

const NOTARY_CA_CERT_PATH: &str = "./src/fixture/tls/rootCA.crt";

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
    let mut certificates: Vec<Certificate> = rustls_pemfile::certs(&mut certificate_file_reader)
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
    let server_task = tokio::spawn(bind_test_server_hyper(server_socket.compat()));

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

    let (mut request_sender, connection) = hyper::client::conn::handshake(tls_connection.compat())
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

    debug!("Done notarization!");
}
