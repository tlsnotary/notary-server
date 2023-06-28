use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct NotaryServerProperties {
    pub server: ServerProperties,
    pub tls_signature: TLSSignatureProperties,
    pub notary_signature: NotarySignatureProperties,
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
pub struct TLSSignatureProperties {
    pub private_key_pem_path: String,
    pub certificate_pem_path: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct NotarySignatureProperties {
    pub private_key_pem_path: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct LoggingProperties {
    pub default_level: String,
}
