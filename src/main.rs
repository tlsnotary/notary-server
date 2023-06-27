mod config;
mod domain;
mod error;
mod server;
mod util;

use error::NotaryServerError;
use eyre::{eyre, Result};
use log::{debug, Level};
use std::str::FromStr;
use structopt::StructOpt;

use config::NotaryServerProperties;
use domain::cli::CliFields;
use server::run_tcp_server;
use util::parse_config_file;

#[tokio::main]
async fn main() -> Result<(), NotaryServerError> {
    // load command line arguments which contains the config file location
    let cli_fields: CliFields = CliFields::from_args();
    let config: NotaryServerProperties = parse_config_file(&cli_fields.config_file)?;

    // set up logger for logging
    let logging_level = &config.logging.default_level;
    simple_logger::init_with_level(
        Level::from_str(logging_level)
            .map_err(|err| eyre!("Something wrong when parsing log level in config: {err}"))?,
    )
    .map_err(|err| eyre!("Something wrong when setting up logger: {err}"))?;
    debug!("Config loaded: {:?}", config);

    // run the tcp server
    run_tcp_server(&config).await?;

    Ok(())
}
