use async_trait::async_trait;
use axum::{
    extract::{rejection::JsonRejection, FromRequestParts, State},
    http::{header, request::Parts, StatusCode},
    response::{IntoResponse, Json},
};
use axum_macros::debug_handler;
use hyper::upgrade::OnUpgrade;
use tracing::{debug, error, info, trace};
use uuid::Uuid;

use crate::{
    domain::notary::{ClientType, NotarizationRequest, NotarizationResponse, NotaryGlobals},
    service::notary_service,
    NotaryServerError,
};

/// Custom extractor used to extract underlying TCP connection for TCP client — using the same upgrade primitives used by
/// the WebSocket implementation where the underlying TCP connection (wrapped in an Upgraded object) only gets polled as an OnUpgrade future
/// after the ongoing HTTP request is finished (ref: https://github.com/tokio-rs/axum/blob/a6a849bb5b96a2f641fa077fe76f70ad4d20341c/axum/src/extract/ws.rs#L122)
///
/// More info on the upgrade primitives: https://docs.rs/hyper/latest/hyper/upgrade/index.html
pub struct TcpConnectionExtractor {
    pub on_upgrade: OnUpgrade,
}

#[async_trait]
impl<S> FromRequestParts<S> for TcpConnectionExtractor
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
                    "Upgrade header is not set for TCP client".to_string(),
                ))?;

        Ok(Self { on_upgrade })
    }
}

/// Handler to configure notarization for both TCP and WebSocket clients, as well as to trigger notarization for TCP client
#[debug_handler(state = NotaryGlobals)]
pub async fn notarize(
    tcp_extractor: Option<TcpConnectionExtractor>,
    State(notary_globals): State<NotaryGlobals>,
    payload: Result<Json<NotarizationRequest>, JsonRejection>,
) -> impl IntoResponse {
    info!(?payload, "Received request for notarization");

    // Parse the body payload
    let payload = match payload {
        Ok(payload) => payload,
        Err(err) => {
            error!("Malformed payload submitted for notarization: {err}");
            return NotaryServerError::BadProverRequest(err.to_string()).into_response();
        }
    };

    // Ensure that the max_transcript_size submitted is not larger than the global max limit configured in notary server
    if payload.max_transcript_size > Some(notary_globals.notarization_config.max_transcript_size) {
        error!(
            "Max transcript size requested {:?} exceeds the maximum threshold {:?}",
            payload.max_transcript_size, notary_globals.notarization_config.max_transcript_size
        );
        return NotaryServerError::BadProverRequest(
            "Max transcript size requested exceeds the maximum threshold".to_string(),
        )
        .into_response();
    }

    let prover_session_id = Uuid::new_v4().to_string();

    // Store the configuration data in a temporary store, currently mainly used for websocket clients
    notary_globals
        .store
        .lock()
        .await
        .insert(prover_session_id.clone(), payload.max_transcript_size);

    trace!("Latest store state: {:?}", notary_globals.store);

    // If the request comes from a TCP client, trigger the notarization process by extracting the underlying TCP connection
    if payload.client_type == ClientType::Tcp {
        let tcp_extractor = match tcp_extractor {
            Some(extractor) => extractor,
            None => {
                let err_msg = "Upgrade header is not set for TCP client".to_string();
                error!(err_msg);
                return NotaryServerError::BadProverRequest(err_msg).into_response();
            }
        };

        let notary_session_id = prover_session_id.clone();

        debug!(
            ?prover_session_id,
            "Spawning notarization thread for tcp client"
        );
        tokio::spawn(async move {
            // Poll the OnUpgrade object to obtain the underlying TCP connection wrapped in Upgraded
            // This future should only return after the original HTTP exchange is done
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
                &notary_globals.notary_signing_key,
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
    }
    // Return the session id in the response to the client
    (
        StatusCode::OK,
        // Need to send Close header so that client can finish the http session and claim the underlying tcp connection for notarization
        [(header::CONNECTION, "Close")],
        Json(NotarizationResponse {
            session_id: prover_session_id,
        }),
    )
        .into_response()
}
