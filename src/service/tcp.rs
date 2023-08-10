use async_trait::async_trait;
use axum::{
    body,
    extract::{rejection::JsonRejection, FromRequestParts, State},
    http::{header, request::Parts, HeaderValue, StatusCode},
    response::{IntoResponse, Json, Response},
};
use axum_macros::debug_handler;
use hyper::upgrade::{OnUpgrade, Upgraded};
use std::future::Future;
use tracing::{error, info, trace};
use uuid::Uuid;

use crate::{
    domain::notary::{NotarizationRequest, NotarizationResponse, NotaryGlobals},
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

impl TcpConnectionExtractor {
    pub fn on_upgrade<C, Fut>(self, callback: C) -> Response
    where
        C: FnOnce(Upgraded) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let on_upgrade = self.on_upgrade;
        tokio::spawn(async move {
            let upgraded = match on_upgrade.await {
                Ok(upgraded) => upgraded,
                Err(err) => {
                    error!("Something wrong with upgrading HTTP: {:?}", err);
                    return;
                }
            };
            callback(upgraded).await;
        });

        #[allow(clippy::declare_interior_mutable_const)]
        const UPGRADE: HeaderValue = HeaderValue::from_static("upgrade");
        #[allow(clippy::declare_interior_mutable_const)]
        const TCP: HeaderValue = HeaderValue::from_static("tcp");

        let builder = Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header(header::CONNECTION, UPGRADE)
            .header(header::UPGRADE, TCP);

        builder.body(body::boxed(body::Empty::new())).unwrap()
    }
}

/// Handler to configure notarization for both TCP and WebSocket clients, as well as to trigger notarization for TCP client
#[debug_handler(state = NotaryGlobals)]
pub async fn initiate(
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

    // Return the session id in the response to the client
    (
        StatusCode::OK,
        Json(NotarizationResponse {
            session_id: prover_session_id,
        }),
    )
        .into_response()
}
