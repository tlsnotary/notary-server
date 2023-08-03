use axum::{
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use tracing::{debug, error, info};
use ws_stream_tungstenite::WsStream;

use crate::{
    axum_websocket::{WebSocket, WebSocketUpgrade},
    domain::notary::NotarizationSetup,
    error::NotaryServerError,
    service::notary_service,
};

/// Handler to upgade websocket connection from http — the session_id header is also extracted here
/// to fetch the configuration parameters that have been submitted in the previous request to /notarize made by
/// the same websocket client
pub async fn upgrade_websocket(
    ws: WebSocketUpgrade,
    mut headers: HeaderMap,
    State(setup): State<NotarizationSetup>,
) -> Response {
    info!("Received websocket request: {:?}", ws);
    let session_id = match headers.remove("X-Session-Id") {
        Some(session_id) => match session_id.to_str() {
            Ok(session_id) => session_id.to_string(),
            Err(err) => {
                let err_msg = format!("X-Session-Id header submitted is not a string: {}", err);
                error!(err_msg);
                return NotaryServerError::BadProverRequest(err_msg).into_response();
            }
        },
        None => {
            let err_msg = "Missing X-Session-Id in WebSocket connection request".to_string();
            error!(err_msg);
            return NotaryServerError::BadProverRequest(err_msg).into_response();
        }
    };
    let max_transcript_size = match setup.store.lock().await.get(&session_id) {
        Some(max_transcript_size) => max_transcript_size.to_owned(),
        None => {
            let err_msg = format!("Session id {} does not exist", session_id);
            error!(err_msg);
            return NotaryServerError::BadProverRequest(err_msg).into_response();
        }
    };

    ws.on_upgrade(move |socket| websocket_notarize(socket, setup, session_id, max_transcript_size))
}

/// Pass the established websocket connection to the notary_service
async fn websocket_notarize(
    socket: WebSocket,
    setup: NotarizationSetup,
    session_id: String,
    max_transcript_size: Option<usize>,
) {
    debug!(?session_id, "Upgraded to websocket connection");
    let stream = WsStream::new(socket.into_inner());
    match notary_service(
        stream,
        &setup.notary_signing_key,
        &session_id,
        max_transcript_size,
    )
    .await
    {
        Ok(_) => {
            info!(?session_id, "Successful notarization using websocket!");
        }
        Err(err) => {
            error!(?session_id, "Failed notarization using websocket: {err}");
        }
    }
}
