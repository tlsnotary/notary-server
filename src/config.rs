use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct NotaryServerProperties {
    pub server: ServerProperties,
    pub signature: SignatureProperties,
    pub logging: LoggingProperties,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ServerProperties {
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SignatureProperties {
    pub private_key_pem_path: String,
    pub certificate_pem_path: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct LoggingProperties {
    pub default_level: String,
}
