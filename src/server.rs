use eyre::{ensure, eyre, Result};
use futures_util::future::poll_fn;
use log::{debug, error, info};
use rustls::{Certificate, PrivateKey, ServerConfig};
use std::{
    io::BufReader,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::{fs::File, net::TcpListener};
use tokio_rustls::TlsAcceptor;

use crate::{
    config::{NotaryServerProperties, SignatureProperties},
    error::NotaryServerError,
};

pub async fn run_tcp_server(config: &NotaryServerProperties) -> Result<(), NotaryServerError> {
    let (private_key, certificates) = load_notary_key_and_cert(&config.signature).await?;

    let tls_config = Arc::new(
        ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certificates, private_key)
            .map_err(|err| eyre!("Failed to instantiate notary server tls config: {err}"))?,
    );

    let notary_address =
        SocketAddr::new(
            IpAddr::V4(
                config.server.host.parse().map_err(|err| {
                    eyre!("Failed to parse notary host address from config: {err}")
                })?,
            ),
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
        let (stream, prover_address) = match poll_fn(|cx| listener.poll_accept(cx)).await {
            Ok(connection) => connection,
            Err(err) => {
                error!("{}", NotaryServerError::ConnectionFailed(err.to_string()));
                continue;
            }
        };
        debug!("Received a prover's TCP connection from {}", prover_address);

        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(_stream) => {
                    info!(
                        "Accepted prover's TLS-secured TCP connection from {}",
                        prover_address
                    );
                }
                Err(err) => {
                    error!("{}", NotaryServerError::ConnectionFailed(err.to_string()));
                }
            }
        });
    }
}

async fn load_notary_key_and_cert(
    config: &SignatureProperties,
) -> Result<(PrivateKey, Vec<Certificate>)> {
    debug!("Loading notary server's private key and certificate");

    let private_key_file = File::open(&config.private_key_pem_path)
        .await?
        .into_std()
        .await;
    let mut private_key_file_reader = BufReader::new(private_key_file);
    let mut private_keys = rustls_pemfile::pkcs8_private_keys(&mut private_key_file_reader)?;
    ensure!(
        private_keys.len() == 1,
        "More than 1 key found in the pem file"
    );
    let private_key = PrivateKey(private_keys.remove(0));

    let certificate_file = File::open(&config.certificate_pem_path)
        .await?
        .into_std()
        .await;
    let mut certificate_file_reader = BufReader::new(certificate_file);
    let certificates = rustls_pemfile::certs(&mut certificate_file_reader)?
        .into_iter()
        .map(Certificate)
        .collect();

    debug!("Successfully loaded notary server's private key and certificate!");
    Ok((private_key, certificates))
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn test_load_notary_key_and_cert() {
        let config = SignatureProperties {
            private_key_pem_path: "./src/fixtures/notary.key".to_string(),
            certificate_pem_path: "./src/fixtures/notary.crt".to_string(),
        };
        let result: Result<(PrivateKey, Vec<Certificate>)> =
            load_notary_key_and_cert(&config).await;
        println!("{:?}", result);
        assert!(result.is_ok(), "Could not load private key and cert");
    }
}
