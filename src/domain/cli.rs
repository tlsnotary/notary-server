use structopt::StructOpt;

/// Fields loaded from the command line when launching a service.
#[derive(Clone, Debug, StructOpt)]
#[structopt(name = "Flight Itinerary Microservice")]
pub struct CliFields {
    /// Configuration file location
    #[structopt(long, default_value = "./src/config/config.yaml")]
    pub config_file: String,
}
