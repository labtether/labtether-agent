//! One HTTP/1.1 JSON POST, for enrollment. The whole exchange has a time
//! limit (Go's client used 15 s) and the answer body has a size limit.

use std::sync::Arc;
use std::time::Duration;

use http::{Request, StatusCode, Uri, header};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;

use crate::net::{self, DialError, Endpoint};

/// Why a POST failed before an answer arrived.
#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("{0}")]
    Dial(#[from] DialError),
    #[error("invalid request address")]
    Address,
    #[error("HTTP exchange failed: {0}")]
    Exchange(#[from] hyper::Error),
    #[error("the answer is larger than {0} bytes")]
    TooLarge(usize),
    #[error("no answer within {0:?}")]
    Timeout(Duration),
}

/// Status and body of an answer.
#[derive(Debug)]
pub struct Answer {
    pub status: StatusCode,
    pub body: Bytes,
}

/// POSTs `body` as JSON to `url`. The body read stops at `max_body` bytes.
pub async fn post_json(
    url: &str,
    body: Vec<u8>,
    tls: &Arc<ClientConfig>,
    timeout: Duration,
    max_body: usize,
) -> Result<Answer, HttpError> {
    match tokio::time::timeout(timeout, exchange(url, body, tls, max_body)).await {
        Ok(result) => result,
        Err(_) => Err(HttpError::Timeout(timeout)),
    }
}

async fn exchange(
    url: &str,
    body: Vec<u8>,
    tls: &Arc<ClientConfig>,
    max_body: usize,
) -> Result<Answer, HttpError> {
    let uri: Uri = url.parse().map_err(|_| HttpError::Address)?;
    let endpoint = Endpoint::from_uri(&uri)?;
    let authority = uri
        .authority()
        .ok_or(HttpError::Address)?
        .as_str()
        .to_owned();
    let path = uri
        .path_and_query()
        .map_or("/", |pq| pq.as_str())
        .to_owned();
    let stream = net::dial(&endpoint, tls).await?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::post(path)
        .header(header::HOST, authority)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::USER_AGENT, "labtether-agent")
        .body(Full::new(Bytes::from(body)))
        .map_err(|_| HttpError::Address)?;
    let response = sender.send_request(request).await;
    let result = match response {
        Ok(response) => {
            let status = response.status();
            match Limited::new(response.into_body(), max_body).collect().await {
                Ok(collected) => Ok(Answer {
                    status,
                    body: collected.to_bytes(),
                }),
                Err(error) => match error.downcast::<hyper::Error>() {
                    Ok(error) => Err(HttpError::Exchange(*error)),
                    Err(_) => Err(HttpError::TooLarge(max_body)),
                },
            }
        }
        Err(error) => Err(HttpError::Exchange(error)),
    };
    driver.abort();
    result
}
