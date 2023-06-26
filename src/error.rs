use eyre::Report;

#[derive(Debug, thiserror::Error)]
pub enum NotaryServerError {
    #[error("Something wrong internally happened: {0}")]
    Internal(#[from] Report),
}
