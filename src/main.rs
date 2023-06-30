mod config;
mod domain;
mod error;
mod server;
mod server_tracing;
mod util;

use eyre::{eyre, Result};
use structopt::StructOpt;
use tracing::debug;

use config::NotaryServerProperties;
use domain::cli::CliFields;
use error::NotaryServerError;
use server::run_tcp_server;
use server_tracing::init_tracing;
use util::parse_config_file;

#[tokio::main]
async fn main() -> Result<(), NotaryServerError> {
    // Load command line arguments which contains the config file location
    let cli_fields: CliFields = CliFields::from_args();
    let config: NotaryServerProperties = parse_config_file(&cli_fields.config_file)?;

    // Set up tracing for logging
    init_tracing(&config).map_err(|err| eyre!("Failed to set up tracing: {err}"))?;

    debug!("Config loaded: {:?}", config);

    // Run the tcp server
    run_tcp_server(&config).await?;

    Ok(())
}
