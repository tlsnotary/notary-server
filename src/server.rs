use eyre::{ensure, eyre, Result};
use futures_util::future::poll_fn;
use log::{debug, error, info};
use p256::ecdsa::{Signature, SigningKey};
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

use crate::{
    config::{NotaryServerProperties, NotarySignatureProperties, TLSSignatureProperties},
    error::NotaryServerError,
};

pub async fn run_tcp_server(config: &NotaryServerProperties) -> Result<(), NotaryServerError> {
    let (tls_private_key, tls_certificates) = load_tls_key_and_cert(&config.tls_signature).await?;
    let notary_signing_key = load_notary_signing_key(&config.notary_signature).await?;

    let tls_config = Arc::new(
        ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(tls_certificates, tls_private_key)
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
        let notary_signing_key = notary_signing_key.clone();

        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(stream) => {
                    info!(
                        "Accepted prover's TLS-secured TCP connection from {}",
                        prover_address
                    );
                    match notary_service(stream, &notary_signing_key).await {
                        Ok(_) => {
                            info!("Successful notarization!");
                        }
                        Err(err) => {
                            error!("Failed notarization: {err}");
                        }
                    }
                }
                Err(err) => {
                    error!("{}", NotaryServerError::ConnectionFailed(err.to_string()));
                }
            }
        });
    }
}

async fn notary_service<T: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    socket: T,
    signing_key: &SigningKey,
) -> Result<(), NotaryServerError> {
    debug!("Starting notarization...");

    let config = NotaryConfig::builder().build()?;
    let (notary, notary_fut) = bind_notary(config, socket.compat())?;

    tokio::spawn(notary_fut);

    notary.notarize::<Signature>(signing_key).await?;

    debug!("Notarization completed successfully!");
    Ok(())
}

async fn read_pem_file(file_path: &str) -> Result<BufReader<StdFile>> {
    let key_file = File::open(file_path).await?.into_std().await;
    Ok(BufReader::new(key_file))
}

async fn load_notary_signing_key(config: &NotarySignatureProperties) -> Result<SigningKey> {
    debug!("Loading notary server's signing key");

    let mut private_key_file_reader = read_pem_file(&config.private_key_pem_path).await?;
    let mut private_keys = rustls_pemfile::pkcs8_private_keys(&mut private_key_file_reader)
        .map_err(|err| {
            eyre!("Failed to read notary signing key pem file for notarization: {err}")
        })?;

    ensure!(
        private_keys.len() == 1,
        "More than 1 key found in the notary signing key pem file"
    );
    let notary_signing_key = SigningKey::from_slice(private_keys.remove(0).as_slice())
        .map_err(|err| eyre!("Failed to load notary signing key for notarization: {err}"))?;

    debug!("Successfully loaded notary server's signing key!");
    Ok(notary_signing_key)
}

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
            private_key_pem_path: "./src/fixtures/notary.key".to_string(),
            certificate_pem_path: "./src/fixtures/notary.crt".to_string(),
        };
        let result: Result<(PrivateKey, Vec<Certificate>)> = load_tls_key_and_cert(&config).await;
        assert!(result.is_ok(), "Could not load tls private key and cert");
    }

    #[tokio::test]
    async fn test_load_notary_signing_key() {
        let config = NotarySignatureProperties {
            private_key_pem_path: "./src/fixtures/notaryEC.key".to_string(),
        };
        let result: Result<SigningKey> = load_notary_signing_key(&config).await;
        println!("{:?}", result);
        assert!(result.is_ok(), "Could not load notary private key");
    }
}
