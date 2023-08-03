use async_trait::async_trait;
use axum::{
    extract::{rejection::JsonRejection, FromRequestParts, State},
    http::{header, request::Parts, StatusCode},
    response::{IntoResponse, Json},
};
use axum_macros::debug_handler;
use hyper::upgrade::OnUpgrade;
use tracing::{debug, error, info};
use uuid::Uuid;

use crate::{
    domain::notary::{ClientType, NotarizationRequest, NotarizationResponse, NotarizationSetup},
    service::notary_service,
    NotaryServerError,
};

/// Custom extractor used to extract underlying TCP connection for TCP client — using the same upgrade primitives used by
/// the WebSocket implementation where the underlying IO wrapped in an Upgrade object only gets polled as an OnUpgrade future
/// after the ongoing HTTP request is finished (ref: https://github.com/tokio-rs/axum/blob/a6a849bb5b96a2f641fa077fe76f70ad4d20341c/axum/src/extract/ws.rs#L122)
///
/// More info on the upgrade primitives: https://docs.rs/hyper/latest/hyper/upgrade/index.html
pub struct RawTcpExtractor {
    pub on_upgrade: OnUpgrade,
}

#[async_trait]
impl<S> FromRequestParts<S> for RawTcpExtractor
where
    S: Send + Sync,
{
    type Rejection = NotaryServerError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let on_upgrade =
            parts
                .extensions
                .remove::<OnUpgrade>()
                .ok_or(NotaryServerError::BadProverRequest(
                    "Upgrade header is not set".to_string(),
                ))?;

        Ok(Self { on_upgrade })
    }
}

/// Handler to configure notarization for both TCP and WebSocket clients, as well as to start notarization for TCP client
#[debug_handler(state = NotarizationSetup)]
pub async fn notarize(
    tcp_extractor: Option<RawTcpExtractor>,
    State(setup): State<NotarizationSetup>,
    payload: Result<Json<NotarizationRequest>, JsonRejection>,
) -> impl IntoResponse {
    info!(?payload, "Received request for notarization");

    let payload = match payload {
        Ok(payload) => payload,
        Err(err) => {
            error!("Malformed payload submitted for notarization: {err}");
            return NotaryServerError::BadProverRequest(err.to_string()).into_response();
        }
    };

    if payload.max_transcript_size > Some(setup.notarization_config.max_transcript_size) {
        error!(
            "Max transcript size requested {:?} exceeds the maximum threshold {:?}",
            payload.max_transcript_size, setup.notarization_config.max_transcript_size
        );
        return NotaryServerError::BadProverRequest(
            "Max transcript size requested exceeds the maximum threshold".to_string(),
        )
        .into_response();
    }

    let prover_session_id = Uuid::new_v4().to_string();
    setup
        .store
        .lock()
        .await
        .insert(prover_session_id.clone(), payload.max_transcript_size);

    debug!("Latest store state: {:?}", setup.store);

    if payload.client_type == ClientType::Tcp {
        let tcp_extractor = match tcp_extractor {
            Some(extractor) => extractor,
            None => {
                let err_msg = "Upgrade header is not set for TCP client".to_string();
                error!(err_msg);
                return NotaryServerError::BadProverRequest(err_msg).into_response();
            }
        };
        debug!(
            ?prover_session_id,
            "Spawning notarization thread for tcp client"
        );
        let notary_session_id = prover_session_id.clone();

        tokio::spawn(async move {
            let stream = match tcp_extractor.on_upgrade.await {
                Ok(upgraded) => upgraded,
                Err(err) => {
                    error!(
                        ?notary_session_id,
                        "Something wrong with upgrading HTTP: {:?}", err
                    );
                    return;
                }
            };
            debug!(?notary_session_id, "Successfully extracted tcp connection");
            match notary_service(
                stream,
                &setup.notary_signing_key,
                &notary_session_id,
                payload.max_transcript_size,
            )
            .await
            {
                Ok(_) => {
                    info!(?notary_session_id, "Successful notarization using raw tcp!");
                }
                Err(err) => {
                    error!(
                        ?notary_session_id,
                        "Failed notarization using raw tcp: {err}"
                    );
                }
            }
        });
        return (
            StatusCode::OK,
            // Need to send close to signal tcp client to close the http connection so that client can extract the underlying tcp connection for notarization
            [(header::CONNECTION, "Close")],
            Json(NotarizationResponse {
                session_id: prover_session_id,
            }),
        )
            .into_response();
    }
    // Don't send close connection to websocket client so that they can reuse the same underlying tcp connection to establish websocket connection
    (
        StatusCode::OK,
        Json(NotarizationResponse {
            session_id: prover_session_id,
        }),
    )
        .into_response()
}
