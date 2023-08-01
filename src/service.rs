pub mod tcp;
pub mod websocket;

use p256::ecdsa::{Signature, SigningKey};
use tlsn_notary::{bind_notary, NotaryConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::debug;

use crate::error::NotaryServerError;

/// Run the notarization
pub async fn notary_service<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    socket: T,
    signing_key: &SigningKey,
    session_id: &str,
    max_transcript_size: Option<usize>,
) -> Result<(), NotaryServerError> {
    debug!(?session_id, "Starting notarization...");

    let mut config_builder = NotaryConfig::builder();

    config_builder.id(session_id);

    if let Some(max_transcript_size) = max_transcript_size {
        config_builder.max_transcript_size(max_transcript_size);
    }

    let config = config_builder.build()?;

    let (notary, notary_fut) = bind_notary(config, socket.compat())?;

    // Run the notary and background processes concurrently
    tokio::try_join!(notary_fut, notary.notarize::<Signature>(signing_key),).map(|_| Ok(()))?
}
