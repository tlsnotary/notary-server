use eyre::Report;
use std::error::Error;

use tlsn_notary::{NotaryConfigBuilderError, NotaryError};

#[derive(Debug, thiserror::Error)]
pub enum NotaryServerError {
    #[error(transparent)]
    Unexpected(#[from] Report),
    #[error("Failed to connect to prover: {0}")]
    ConnectionFailed(String),
    #[error("Error occurred during notarization: {0}")]
    NotaryError(Box<dyn Error + Send + 'static>),
}

impl From<NotaryError> for NotaryServerError {
    fn from(error: NotaryError) -> Self {
        Self::NotaryError(Box::new(error))
    }
}

impl From<NotaryConfigBuilderError> for NotaryServerError {
    fn from(error: NotaryConfigBuilderError) -> Self {
        Self::NotaryError(Box::new(error))
    }
}
