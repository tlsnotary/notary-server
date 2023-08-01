use async_tungstenite::tokio::connect_async_with_tls_connector;
use futures::AsyncWriteExt;
use hyper::{body::to_bytes, client::conn::Parts, Body, Request, StatusCode};
use rustls::{Certificate, ClientConfig, RootCertStore};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tls_server_fixture::{bind_test_server, CA_CERT_DER, SERVER_DOMAIN};
use tlsn_prover::{bind_prover, ProverConfig};
use tokio_rustls::TlsConnector;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::debug;
use ws_stream_tungstenite::WsStream;

use notary_server::{
    read_pem_file, run_server, NotarizationProperties, NotarizationRequest, NotarizationResponse,
    NotaryServerProperties, NotarySignatureProperties, ServerProperties, TLSSignatureProperties,
    TracingProperties,
};

const NOTARY_CA_CERT_PATH: &str = "./src/fixture/tls/rootCA.crt";
const NOTARY_CA_CERT_BYTES: &[u8] = include_bytes!("../src/fixture/tls/rootCA.crt");

async fn setup_config_and_server(sleep_ms: u64, port: u16) -> NotaryServerProperties {
    let notary_config = NotaryServerProperties {
        server: ServerProperties {
            name: "tlsnotaryserver.io".to_string(),
            domain: "127.0.0.1".to_string(),
            port,
        },
        notarization: NotarizationProperties {
            max_transcript_size: 1 << 14,
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

    let _ = tracing_subscriber::fmt::try_init();

    let config = notary_config.clone();

    // Run the the notary server
    tokio::spawn(async move {
        run_server(&config).await.unwrap();
    });

    // Sleep for a while to allow notary server to finish set up and start listening
    tokio::time::sleep(Duration::from_millis(sleep_ms)).await;

    notary_config
}

#[tokio::test]
async fn test_raw_prover() {
    // Setup
    let notary_config = setup_config_and_server(100, 7048).await;

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

    let notary_domain = notary_config.server.domain.clone();
    let notary_port = notary_config.server.port;
    let notary_socket = tokio::net::TcpStream::connect(SocketAddr::new(
        IpAddr::V4(notary_domain.parse().unwrap()),
        notary_port,
    ))
    .await
    .unwrap();

    let notary_tls_socket = notary_connector
        .connect(
            notary_config.server.name.as_str().try_into().unwrap(),
            notary_socket,
        )
        .await
        .unwrap();

    // Attach the hyper HTTP client to the notary TLS connection to send notarization request via HTTP
    // i.e. this can be used to show API key, set cipher suite, max transcript size and to obtain notarization session id
    let (mut request_sender, connection) = hyper::client::conn::handshake(notary_tls_socket)
        .await
        .unwrap();

    // Spawn the HTTP task to be run concurrently
    let connection_task = tokio::spawn(connection.without_shutdown());

    // Build the HTTP request to fetch the DMs
    let payload = serde_json::to_string(&NotarizationRequest {
        client_type: notary_server::ClientType::Tcp,
        max_transcript_size: Some(notary_config.notarization.max_transcript_size),
    })
    .unwrap();
    let request = Request::builder()
        .uri(format!("https://{notary_domain}:{notary_port}/notarize"))
        .method("POST")
        .header("Host", notary_domain)
        .header("Connection", "Upgrade")
        // Need to specify this upgrade header for server to extract tcp connection later
        .header("Upgrade", "TCP")
        // Need to specify application/json for axum to parse it as json
        .header("Content-Type", "application/json")
        .body(Body::from(payload))
        .unwrap();

    debug!("Sending request");

    let response = request_sender.send_request(request).await.unwrap();

    debug!("Sent request");

    assert!(response.status() == StatusCode::OK);

    debug!("Response OK");

    // Pretty printing :)
    let payload = to_bytes(response.into_body()).await.unwrap().to_vec();
    let response =
        serde_json::from_str::<NotarizationResponse>(&String::from_utf8_lossy(&payload)).unwrap();

    debug!("Notarization response: {:?}", response,);

    // Claim back the TLS socket after HTTP exchange is done
    let Parts {
        io: notary_tls_socket,
        ..
    } = connection_task.await.unwrap().unwrap();

    // Connect to the Server
    let (client_socket, server_socket) = tokio::io::duplex(2 << 16);
    let server_task = tokio::spawn(bind_test_server(server_socket.compat()));

    let mut root_store = tls_core::anchors::RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();

    // Basic default prover config — use local address as the notarization session id
    let prover_config = ProverConfig::builder()
        .id(response.session_id)
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

#[tokio::test]
async fn test_websocket_prover() {
    // Setup
    let notary_config = setup_config_and_server(100, 7049).await;

    // Connect to the Notary via Websocket
    let certificate =
        tokio_native_tls::native_tls::Certificate::from_pem(NOTARY_CA_CERT_BYTES).unwrap();
    let notary_connector = tokio_native_tls::native_tls::TlsConnector::builder()
        .add_root_certificate(certificate)
        .use_sni(false)
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let notary_domain = notary_config.server.domain.clone();
    let notary_port = notary_config.server.port;
    let (notary_ws_stream, _) = connect_async_with_tls_connector(
        format!("wss://{notary_domain}:{notary_port}/ws-notarize"),
        Some(notary_connector.into()),
    )
    .await
    .unwrap();

    // Wrap the socket with the adapter so that we get AsyncRead and AsyncWrite implemented
    let notary_ws_socket = WsStream::new(notary_ws_stream);

    // Connect to the Server
    let (client_socket, server_socket) = tokio::io::duplex(2 << 16);
    let server_task = tokio::spawn(bind_test_server(server_socket.compat()));

    let mut root_store = tls_core::anchors::RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();

    // Basic default prover config — use local address as the notarization session id
    let prover_config = ProverConfig::builder()
        .id("test-websocket")
        .server_dns(SERVER_DOMAIN)
        .root_cert_store(root_store)
        .build()
        .unwrap();

    // Bind the Prover to the sockets
    let (tls_connection, prover_fut, mux_fut) =
        bind_prover(prover_config, client_socket.compat(), notary_ws_socket)
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
