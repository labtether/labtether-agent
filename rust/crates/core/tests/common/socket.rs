//! The stand-in Hub's WebSocket side.

use std::sync::Arc;

use data_encoding::BASE64;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use futures_util::{SinkExt, StreamExt};
use http::HeaderValue;
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message as Frame;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

use super::{Event, Head, Pending, Prefixed, Shared, emit, kick_receiver, next_id, push_receiver};

fn bearer(head: &Head) -> Option<String> {
    head.headers
        .get("authorization")
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::to_owned)
}

// The callback's error type is fixed by tungstenite's `Callback` trait.
#[allow(clippy::result_large_err)]
pub(super) async fn serve_ws<S>(mut stream: Prefixed<S>, head: Head, shared: Arc<Shared>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if shared.behaviour.lock().unwrap().refuse_upgrade {
        emit(
            &shared,
            Event::Refused {
                status: 503,
                headers: head.headers.clone(),
            },
        );
        let _ = stream
            .write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
        let _ = stream.shutdown().await;
        return;
    }
    let read_pause = shared.behaviour.lock().unwrap().read_pause;
    let (accepted, refused_pending, canonical, stall, pending, close_at_once) = {
        let behaviour = shared.behaviour.lock().unwrap();
        let token = bearer(&head);
        let pending = token.is_none()
            && head
                .headers
                .get("x-request-enrollment")
                .is_some_and(|v| v == "true");
        let refused_pending = pending && behaviour.refuse_pending;
        let accepted = token
            .as_ref()
            .is_some_and(|t| behaviour.accepted_tokens.contains(t))
            || (pending && !refused_pending);
        (
            accepted,
            refused_pending,
            behaviour.canonical_asset.clone(),
            behaviour.stall,
            pending,
            behaviour.close_at_once,
        )
    };
    if !accepted {
        let (status, line) = if refused_pending {
            (403, "403 Forbidden")
        } else {
            (401, "401 Unauthorized")
        };
        emit(
            &shared,
            Event::Refused {
                status,
                headers: head.headers.clone(),
            },
        );
        let answer = format!("HTTP/1.1 {line}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        let _ = stream.write_all(answer.as_bytes()).await;
        let _ = stream.shutdown().await;
        return;
    }
    let callback = move |_: &Request, mut response: Response| {
        if let (Some(asset), false) = (&canonical, pending) {
            response.headers_mut().insert(
                "x-labtether-asset-id",
                HeaderValue::from_str(asset).unwrap(),
            );
        }
        Ok(response)
    };
    let Ok(mut socket) = tokio_tungstenite::accept_hdr_async(stream, callback).await else {
        return;
    };
    // Subscribe before telling the test the agent is connected: a message
    // the test sends as soon as it sees `Connected` must reach this socket
    // (a broadcast sent before the subscription is lost).
    let mut kick = kick_receiver(&shared);
    let mut push = push_receiver(&shared);
    let id = next_id(&shared);
    emit(
        &shared,
        Event::Connected {
            id,
            headers: head.headers.clone(),
        },
    );
    if close_at_once {
        let _ = socket.close(None).await;
        emit(&shared, Event::Closed { id });
        return;
    }
    if stall {
        // Hold the socket without reading: no pongs reach the agent.
        let _ = kick.changed().await;
        return;
    }
    if pending {
        let challenge = json!({"type": "enrollment.challenge", "data": {"connection_id": format!("conn-{id}"), "nonce": "nonce-1"}});
        let _ = socket.send(Frame::text(challenge.to_string())).await;
    }
    loop {
        tokio::select! {
            frame = socket.next() => match frame {
                Some(Ok(Frame::Text(text))) => {
                    let message: Value = serde_json::from_str(text.as_str()).unwrap_or(Value::Null);
                    emit(&shared, Event::Message { id, message: message.clone() });
                    if !read_pause.is_zero() {
                        tokio::time::sleep(read_pause).await;
                    }
                    if message["type"] == "enrollment.proof" {
                        let valid = proof_is_valid(&message["data"]);
                        emit(&shared, Event::Proof { valid });
                        let pending = shared.behaviour.lock().unwrap().pending.clone();
                        let reply = match pending {
                            Pending::Approve { token, asset_id } if valid => {
                                shared.behaviour.lock().unwrap().accepted_tokens.insert(token.clone());
                                Some(json!({"type": "enrollment.approved", "data": {"token": token, "asset_id": asset_id}}))
                            }
                            Pending::Reject => Some(json!({"type": "enrollment.rejected", "data": {"reason": "An admin rejected this device in LabTether."}})),
                            _ => None,
                        };
                        if let Some(reply) = reply {
                            let rejected = reply["type"] == "enrollment.rejected";
                            let _ = socket.send(Frame::text(reply.to_string())).await;
                            if rejected {
                                // The Hub closes a rejected pending socket.
                                let _ = socket.close(None).await;
                                break;
                            }
                        }
                    }
                }
                Some(Ok(Frame::Close(_))) | None | Some(Err(_)) => break,
                Some(Ok(_)) => {}
            },
            _ = kick.changed() => {
                let _ = socket.close(None).await;
                break;
            }
            Ok(text) = push.recv() => {
                let _ = socket.send(Frame::text(text)).await;
            }
        }
    }
    emit(&shared, Event::Closed { id });
}

/// Checks the proof as the Hub does: the signature over
/// `labtether-enrollment-proof|connection_id|nonce|fingerprint`.
fn proof_is_valid(data: &Value) -> bool {
    let field = |name: &str| data[name].as_str().unwrap_or_default().to_owned();
    let Ok(public) = BASE64.decode(field("public_key").as_bytes()) else {
        return false;
    };
    let Ok(signature) = BASE64.decode(field("signature").as_bytes()) else {
        return false;
    };
    let (Ok(public), Ok(signature)) = (
        <[u8; 32]>::try_from(public),
        <[u8; 64]>::try_from(signature),
    ) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(&public) else {
        return false;
    };
    let payload = format!(
        "labtether-enrollment-proof|{}|{}|{}",
        field("connection_id"),
        field("nonce"),
        field("fingerprint")
    );
    key.verify(payload.as_bytes(), &Signature::from_bytes(&signature))
        .is_ok()
        && field("fingerprint") == labtether_agent_core::identity::fingerprint(&public)
}
