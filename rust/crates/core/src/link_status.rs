//! What the agent knows about its Hub connection, for the local status
//! page. Ported from the Go agent's `wsTransport` fields and its
//! `ConnectionState`, `ConnectionErrorReason` and `EnrollmentRefusal`
//! (`ws_transport.go`), set from the same places: the reconnect loop, the
//! session end, start-up enrollment, re-enrollment and the enrollment
//! messages.
//!
//! Go reads `connected` and the state under two separate locks; here one
//! read under one lock gives both, so they always agree.

use std::sync::{Mutex, MutexGuard};
use std::time::SystemTime;

/// `connection_state` on the status page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Connected,
    Connecting,
    AuthFailed,
    Disconnected,
}

impl ConnectionState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Connecting => "connecting",
            Self::AuthFailed => "auth_failed",
            Self::Disconnected => "disconnected",
        }
    }
}

/// Go's `connectErrorKind` for a failed connect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    /// The Hub answered 401 or 403.
    Auth,
    /// Anything else.
    Transient,
}

/// Go's `agentTokenPersistenceFailed`.
pub const TOKEN_PERSISTENCE_FAILED: &str = "agent_token_persistence_failed";
/// The re-enrollment cleanup code Go adds in `reEnrollAgainstActiveHub`.
pub const TOKEN_CLEANUP_FAILED: &str = "consumed_enrollment_token_cleanup_failed";
/// Go's `enrollmentTokenRejected`.
pub const ENROLLMENT_TOKEN_REJECTED: &str = "enrollment_token_rejected";

#[derive(Debug, Default)]
struct Fields {
    /// Go's `connected`: a socket is open, pending or with a token.
    socket_open: bool,
    pending_enrollment: bool,
    last_error: Option<FailureKind>,
    last_error_reason: Option<&'static str>,
    disconnected_at: Option<SystemTime>,
    /// Go's `credentialPersistenceError`; empty when none.
    persistence: String,
    /// Go's `credentialError`: the one-use token was refused at start.
    credential_rejected: bool,
    /// Go's `enrollmentRefusal`: the Hub's words, one line.
    refusal: String,
}

/// The connection part of the status page, read under one lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionView {
    pub connected: bool,
    pub state: ConnectionState,
    pub last_error: Option<String>,
    pub last_error_reason: Option<&'static str>,
    pub disconnected_at: Option<SystemTime>,
    pub enrollment_error: Option<String>,
}

/// The shared connection status.
#[derive(Debug, Default)]
pub struct LinkStatus(Mutex<Fields>);

impl LinkStatus {
    fn lock(&self) -> MutexGuard<'_, Fields> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// A socket opened (Go: the end of `connectWithResponse`).
    pub fn opened(&self, pending_enrollment: bool) {
        let mut fields = self.lock();
        fields.socket_open = true;
        fields.pending_enrollment = pending_enrollment;
        fields.last_error = None;
        fields.last_error_reason = None;
        fields.disconnected_at = None;
    }

    /// The socket closed (Go: `markDisconnected`).
    pub fn closed(&self) {
        let mut fields = self.lock();
        fields.socket_open = false;
        fields.pending_enrollment = false;
        fields.disconnected_at.get_or_insert_with(SystemTime::now);
    }

    /// A connect attempt failed (Go: the failure branch of `reconnectLoop`).
    pub fn failed(&self, kind: FailureKind, reason: Option<&'static str>) {
        let mut fields = self.lock();
        fields.last_error = Some(kind);
        fields.last_error_reason = reason;
        fields.disconnected_at.get_or_insert_with(SystemTime::now);
    }

    /// The reconnect loop ended (Go: its deferred clean-up).
    pub fn loop_stopped(&self) {
        {
            let mut fields = self.lock();
            fields.last_error = None;
            fields.last_error_reason = None;
        }
        self.closed();
    }

    /// Re-enrollment gave a new token (Go: `updateToken`).
    pub fn token_replaced(&self) {
        let mut fields = self.lock();
        fields.last_error = None;
        fields.last_error_reason = None;
        fields.credential_rejected = false;
        fields.refusal.clear();
    }

    /// Go's `setCredentialPersistenceError`; empty clears it.
    pub fn set_persistence(&self, code: &str) {
        self.lock().persistence = code.trim().to_owned();
    }

    /// Go's `setCredentialError` with `enrollment_token_rejected` or "".
    pub fn set_credential_rejected(&self, rejected: bool) {
        self.lock().credential_rejected = rejected;
    }

    /// Go's `setEnrollmentRefusal`: the Hub's words, already one line.
    pub fn set_refusal(&self, words: &str) {
        self.lock().refusal = words.trim().to_owned();
    }

    /// Go's `ConnectionState`, `ConnectionErrorReason`, `Connected` and
    /// `EnrollmentRefusal` together.
    pub fn view(&self) -> ConnectionView {
        let fields = self.lock();
        let connected = fields.socket_open && !fields.pending_enrollment;
        let text = |value: &str| (!value.is_empty()).then(|| value.to_owned());
        let (state, last_error, disconnected_at) = if fields.credential_rejected {
            (
                ConnectionState::AuthFailed,
                Some(ENROLLMENT_TOKEN_REJECTED.to_owned()),
                fields.disconnected_at,
            )
        } else if fields.socket_open && fields.pending_enrollment {
            (
                ConnectionState::Connecting,
                Some("enrollment_pending".to_owned()),
                None,
            )
        } else if fields.socket_open {
            (ConnectionState::Connected, text(&fields.persistence), None)
        } else {
            match fields.last_error {
                Some(FailureKind::Auth) => (
                    ConnectionState::AuthFailed,
                    Some("auth_failed".to_owned()),
                    fields.disconnected_at,
                ),
                Some(FailureKind::Transient) => (
                    ConnectionState::Connecting,
                    Some("transient".to_owned()),
                    fields.disconnected_at,
                ),
                None if !fields.persistence.is_empty() => (
                    ConnectionState::Connecting,
                    text(&fields.persistence),
                    fields.disconnected_at,
                ),
                None => (ConnectionState::Disconnected, None, fields.disconnected_at),
            }
        };
        let reason_hidden =
            fields.socket_open || fields.credential_rejected || fields.last_error.is_none();
        ConnectionView {
            connected,
            state,
            last_error,
            last_error_reason: if reason_hidden {
                None
            } else {
                fields.last_error_reason
            },
            disconnected_at,
            enrollment_error: if connected {
                None
            } else {
                text(&fields.refusal)
            },
        }
    }
}

/// Go's `printableOneLine`: printable characters only, runs of white space
/// or control characters as one space, at most `max` characters.
pub fn printable_one_line(text: &str, max: usize) -> String {
    let mut out = String::new();
    let mut count = 0;
    let mut space = false;
    for c in text.chars() {
        if c.is_whitespace() || c.is_control() {
            space = !out.is_empty();
            continue;
        }
        if count >= max {
            break;
        }
        if space {
            out.push(' ');
            count += 1;
            space = false;
        }
        out.push(c);
        count += 1;
    }
    out
}
