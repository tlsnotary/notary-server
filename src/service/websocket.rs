use async_trait::async_trait;
use axum::{
    extract::{FromRequestParts, State},
    http::{header, request::Parts, HeaderMap},
    response::{IntoResponse, Response},
};
use hyper::upgrade::Upgraded;
use tracing::{debug, error, info};
use ws_stream_tungstenite::WsStream;

use crate::{
    axum_websocket::{header_eq, WebSocket, WebSocketUpgrade},
    domain::notary::NotaryGlobals,
    error::NotaryServerError,
    service::{notary_service, tcp::TcpConnectionExtractor},
};

pub struct ProtocolExtractor {
    pub tcp_extractor: Option<TcpConnectionExtractor>,
    pub ws_extractor: Option<WebSocketUpgrade>,
}

#[async_trait]
impl<S> FromRequestParts<S> for ProtocolExtractor
where
    S: Send + Sync,
{
    type Rejection = NotaryServerError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        if header_eq(&parts.headers, header::UPGRADE, "websocket") {
            let ws_extractor = WebSocketUpgrade::from_request_parts(parts, state)
                .await
                .map_err(|err| NotaryServerError::BadProverRequest(err.to_string()))?;
            return Ok(Self {
                tcp_extractor: None,
                ws_extractor: Some(ws_extractor),
            });
        } else if header_eq(&parts.headers, header::UPGRADE, "tcp") {
            let tcp_extractor = TcpConnectionExtractor::from_request_parts(parts, state)
                .await
                .map_err(|err| NotaryServerError::BadProverRequest(err.to_string()))?;
            return Ok(Self {
                tcp_extractor: Some(tcp_extractor),
                ws_extractor: None,
            });
        } else {
            return Err(NotaryServerError::BadProverRequest(
                "Upgrade header is not set for client".to_string(),
            ));
        }
    }
}

/// Handler to upgade websocket connection from http — the session_id header is also extracted here
/// to fetch the configuration parameters that have been submitted in the previous request to /notarize made by
/// the same websocket client
pub async fn switch_protocol(
    protocol: ProtocolExtractor,
    mut headers: HeaderMap,
    State(notary_globals): State<NotaryGlobals>,
) -> Response {
    info!("Received switch protocol request");
    // Extract the session_id from the headers
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
            let err_msg = "Missing X-Session-Id in connection request".to_string();
            error!(err_msg);
            return NotaryServerError::BadProverRequest(err_msg).into_response();
        }
    };
    // Fetch the configuration data from the store using the session_id
    let max_transcript_size = match notary_globals.store.lock().await.get(&session_id) {
        Some(max_transcript_size) => max_transcript_size.to_owned(),
        None => {
            let err_msg = format!("Session id {} does not exist", session_id);
            error!(err_msg);
            return NotaryServerError::BadProverRequest(err_msg).into_response();
        }
    };
    // This completes the HTTP Upgrade request and returns a successful response to the client, meanwhile initiating the websocket connection
    if let Some(ws) = protocol.ws_extractor {
        #[allow(clippy::needless_return)]
        return ws.on_upgrade(move |socket| {
            websocket_notarize(socket, notary_globals, session_id, max_transcript_size)
        });
    } else if let Some(tcp) = protocol.tcp_extractor {
        return tcp.on_upgrade(move |stream| {
            tcp_notarize(stream, notary_globals, session_id, max_transcript_size)
        });
    } else {
        unreachable!();
    }
}

/// Perform notarization using the established websocket connection
async fn websocket_notarize(
    socket: WebSocket,
    notary_globals: NotaryGlobals,
    session_id: String,
    max_transcript_size: Option<usize>,
) {
    debug!(?session_id, "Upgraded to websocket connection");
    // Wrap the websocket in WsStream so that we have AsyncRead and AsyncWrite implemented
    let stream = WsStream::new(socket.into_inner());
    match notary_service(
        stream,
        &notary_globals.notary_signing_key,
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

/// Perform notarization using the established websocket connection
async fn tcp_notarize(
    stream: Upgraded,
    notary_globals: NotaryGlobals,
    session_id: String,
    max_transcript_size: Option<usize>,
) {
    debug!(?session_id, "Upgraded to tcp connection");
    // Wrap the websocket in WsStream so that we have AsyncRead and AsyncWrite implemented
    match notary_service(
        stream,
        &notary_globals.notary_signing_key,
        &session_id,
        max_transcript_size,
    )
    .await
    {
        Ok(_) => {
            info!(?session_id, "Successful notarization using tcp!");
        }
        Err(err) => {
            error!(?session_id, "Failed notarization using tcp: {err}");
        }
    }
}
