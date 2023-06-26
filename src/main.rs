mod config;
mod domain;
mod error;
mod util;

use error::NotaryServerError;
use eyre::Result;
use structopt::StructOpt;

use config::NotaryServerProperties;
use domain::cli::CliFields;
use util::parse_config_file;

#[tokio::main]
async fn main() -> Result<(), NotaryServerError> {
    // load command line argument which is config file location
    let cli_fields: CliFields = CliFields::from_args();
    let config: NotaryServerProperties = parse_config_file(&cli_fields.config_file)?;
    println!("Config: {:?}", config);
    Ok(())
}
