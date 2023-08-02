use std::{sync::Arc, collections::HashMap};

use p256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::config::NotarizationProperties;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotarizationResponse {
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotarizationRequest {
    pub client_type: ClientType,
    pub max_transcript_size: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClientType {
    Tcp,
    Websocket,
}

#[derive(Clone, Debug)]
pub struct NotarizationSetup {
    pub notary_signing_key: SigningKey,
    pub notarization_config: NotarizationProperties,
    pub store: Arc<Mutex<HashMap<String, Option<usize>>>>,
}
