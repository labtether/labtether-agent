//! The Users page: `users.list`, ported from Go's `HandleUsersList` and
//! `collectUserSessionsWho` (`internal/agentcore/system/users.go`).
//! Advertised as `cap_users=list`; Go advertises nothing for it and the
//! Hub offers it to every Linux Go agent.
//!
//! Go runs `who` with no arguments, with the cleaned child environment, the
//! 8 MiB combined output limit and no timeout, and parses its output (see
//! `labtether_agent_platform::who`). Here `who` runs through the command
//! rules with the same settings. When `who` is missing, refused, exits
//! non-zero or prints too much, the reply has no sessions and Go's error
//! text, which the Hub shows.

use std::time::{SystemTime, UNIX_EPOCH};

use labtether_agent_config::Settings;
use labtether_agent_core::Features;
use labtether_agent_platform::gotime::{Zone, local_zone};
use labtether_agent_platform::who::{Session, parse_who};
use labtether_agent_platform::{LookPathError, look_path};
use labtether_agent_security::{CommandPolicy, RunError, RunRequest, go_outcome};
use labtether_protocol::{
    MSG_USERS_LIST, MSG_USERS_LISTED, UserSession, UsersListData, UsersListedData,
};

use crate::commands::Commands;

pub fn register(features: &mut Features, settings: &Settings, commands: &Commands) {
    // Go's `time.Local`, read once for the life of the agent.
    let zone = local_zone(settings.time_zone.as_deref());
    let policy = commands.policy.clone();
    features.on_request(
        MSG_USERS_LIST,
        MSG_USERS_LISTED,
        request_id,
        move |request| answer(request, collect(&policy, &zone)),
    );
}

fn request_id(request: &UsersListData) -> &str {
    &request.request_id
}

/// The `who` Go runs: no arguments, no timeout, Go's output limit.
pub(crate) fn who_request() -> RunRequest {
    let mut request = RunRequest::new("who", Vec::<String>::new());
    request.timeout = None;
    // Go's exec.Cmd waits for the output pipes with no limit (WaitDelay 0).
    request.wait_delay = None;
    request
}

/// Go's `collectUserSessionsWho`: `exec.LookPath("who")` first (its error
/// is the reply's), then `who` through the command rules, with Go's text
/// for a refusal, a non-zero exit or too much output.
pub(crate) fn collect(policy: &CommandPolicy, zone: &Zone) -> Result<Vec<Session>, String> {
    if let Err(error) = look_path("who", policy.search_path()) {
        let error = match error {
            LookPathError::NotFound => RunError::NotFound("who".into()),
            LookPathError::RelativeToCurrentDir => RunError::RelativeToCurrentDir("who".into()),
        };
        return Err(error.to_string());
    }
    let request = who_request();
    let outcome = go_outcome(policy.run(&request), request.output_limit);
    match outcome.error {
        Some(error) => Err(error),
        None => Ok(parse_who(&outcome.output, zone, now())),
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

fn user_session(session: Session) -> UserSession {
    UserSession {
        username: session.username,
        terminal: session.terminal,
        remote_host: session.remote_host,
        login_time: session.login_time,
        session_type: String::new(),
        display: String::new(),
    }
}

/// The reply: the sessions, or Go's error text and no sessions.
pub(crate) fn answer(
    request: UsersListData,
    sessions: Result<Vec<Session>, String>,
) -> UsersListedData {
    match sessions {
        Ok(sessions) => UsersListedData {
            request_id: request.request_id,
            sessions: sessions.into_iter().map(user_session).collect(),
            error: String::new(),
        },
        Err(error) => {
            log::warn!("users: failed to collect user sessions: {error}");
            UsersListedData {
                request_id: request.request_id,
                sessions: Vec::new(),
                error,
            }
        }
    }
}
