//! The agent's Hub identity (token, asset ID, group, addresses) and how it is
//! chosen at start and committed after enrollment. Ported from Go's
//! `resolveTokenWithIdentity`, `restoreEnrollmentState`,
//! `holdTokenForOtherHub` and the enrollment commit in `enroll.go`.

use std::sync::{Arc, Mutex, MutexGuard};

use labtether_agent_config::urls::{self, UrlKind};
use labtether_agent_config::{EnrollmentToken, Secret, Settings};

use crate::state::{EnrollmentState, StateFiles, merge_origins};

/// Token, asset and Hub addresses used for every connection. Replaced as a
/// whole so a token is never paired with another Hub's asset or address.
#[derive(Debug, Clone, Default)]
pub struct HubIdentity {
    pub token: Option<Secret>,
    pub asset_id: String,
    pub group_id: String,
    /// True once the Hub has said which group the asset is in.
    pub group_known: bool,
    pub ws_url: String,
    pub api_url: String,
}

/// The one shared copy of [`HubIdentity`]. Held only for short reads and
/// writes, never across an await.
#[derive(Debug, Clone, Default)]
pub struct IdentityCell(Arc<Mutex<HubIdentity>>);

impl IdentityCell {
    pub fn new(identity: HubIdentity) -> Self {
        Self(Arc::new(Mutex::new(identity)))
    }

    fn lock(&self) -> MutexGuard<'_, HubIdentity> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn snapshot(&self) -> HubIdentity {
        self.lock().clone()
    }

    pub fn replace(&self, identity: HubIdentity) {
        *self.lock() = identity;
    }

    /// Go's `AdoptCanonicalAsset`: returns true when the asset ID changed.
    pub fn adopt_asset(&self, asset_id: &str) -> bool {
        let mut identity = self.lock();
        if identity.asset_id == asset_id {
            return false;
        }
        identity.asset_id = asset_id.to_owned();
        true
    }
}

/// Where the commit of a newly issued token stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitOutcome {
    /// Token and state are on disk.
    Saved,
    /// The token could not be written. Any older token file was removed, so a
    /// restart cannot pick up a stale credential; this one is memory-only.
    MemoryOnly,
}

/// Writes a newly issued token and its state. Go's order: token first; on
/// failure remove any stale token file and keep the token in memory only;
/// otherwise write the state (a failure there is logged).
pub fn commit(files: &StateFiles, identity: &HubIdentity, origins: Vec<String>) -> CommitOutcome {
    let Some(token) = identity.token.as_ref() else {
        return CommitOutcome::MemoryOnly;
    };
    if let Err(error) = files.save_token(token) {
        match files.remove_token() {
            Ok(()) => log::error!(
                "enrollment succeeded but the token could not be saved ({error}); the old token file was removed and the new token is kept in memory only"
            ),
            Err(remove) => log::error!(
                "enrollment succeeded but the token could not be saved ({error}) and the old token file could not be removed ({remove})"
            ),
        }
        return CommitOutcome::MemoryOnly;
    }
    log::info!("token saved to {}", files.token.display());
    let state = EnrollmentState {
        asset_id: identity.asset_id.clone(),
        group_id: identity.group_known.then(|| identity.group_id.clone()),
        hub_ws_url: identity.ws_url.clone(),
        hub_api_url: identity.api_url.clone(),
        token_origins: origins,
        ..EnrollmentState::default()
    };
    if let Err(error) = files.save_state(state) {
        log::warn!("could not save the enrollment state: {error}");
    }
    CommitOutcome::Saved
}

/// The identity before any enrollment: configured values only.
pub fn configured_identity(settings: &Settings) -> HubIdentity {
    let insecure = settings.allow_insecure_transport;
    let api_url = if settings.api_url.is_empty() {
        urls::api_from_ws(&settings.ws_url, insecure)
    } else {
        settings.api_url.clone()
    };
    HubIdentity {
        token: None,
        asset_id: settings.asset_id.clone(),
        group_id: settings.group_id.clone(),
        group_known: false,
        ws_url: settings.ws_url.clone(),
        api_url,
    }
}

/// Go's `restoreEnrollmentState`: the saved asset ID is the Hub's, and a
/// configured address wins over the saved one.
pub fn restore(files: &StateFiles, identity: &mut HubIdentity, settings: &Settings) {
    let insecure = settings.allow_insecure_transport;
    let state = match files.load_state() {
        Ok(Some(state)) => state,
        Ok(None) => return,
        Err(error) => {
            log::warn!("could not restore the enrollment state: {error}");
            return;
        }
    };
    identity.asset_id = state.asset_id.trim().to_owned();
    if let Some(group) = &state.group_id {
        identity.group_id = group.trim().to_owned();
        identity.group_known = true;
    }
    let configured_ws = urls::normalize(&settings.ws_url, UrlKind::WebSocket, insecure);
    let configured_api = urls::normalize(&settings.api_url, UrlKind::Api, insecure);
    let saved_ws = urls::normalize(&state.hub_ws_url, UrlKind::WebSocket, insecure);
    let saved_api = urls::normalize(&state.hub_api_url, UrlKind::Api, insecure);
    (identity.ws_url, identity.api_url) =
        match (configured_ws.is_empty(), configured_api.is_empty()) {
            (false, false) => (configured_ws, configured_api),
            (false, true) => (
                configured_ws.clone(),
                urls::api_from_ws(&configured_ws, insecure),
            ),
            (true, false) => (
                urls::ws_from_api(&configured_api, &saved_ws, insecure),
                configured_api,
            ),
            (true, true) => {
                let api = if saved_api.is_empty() {
                    urls::api_from_ws(&saved_ws, insecure)
                } else {
                    saved_api
                };
                (saved_ws, api)
            }
        };
    hold_token_for_other_hub(files, identity, state);
}

/// Go's `holdTokenForOtherHub`: never send the saved token to a Hub address
/// it was not issued for.
fn hold_token_for_other_hub(
    files: &StateFiles,
    identity: &mut HubIdentity,
    mut state: EnrollmentState,
) {
    if state.token_origins.is_empty() {
        state.token_origins = merge_origins(
            &[],
            &[
                &state.hub_ws_url,
                &state.hub_api_url,
                &identity.ws_url,
                &identity.api_url,
            ],
        );
        if let Err(error) = files.save_state(state) {
            log::warn!("could not record the Hub addresses for the saved token: {error}");
        }
        return;
    }
    for target in [&identity.ws_url, &identity.api_url] {
        if let Some(origin) = urls::origin(target)
            && !state.token_origins.contains(&origin)
        {
            log::warn!(
                "the saved agent token was issued by another Hub address, so it is not sent to {origin}. Stage an enrollment token from that Hub to enroll this agent there."
            );
            identity.token = None;
            return;
        }
    }
}

/// The start-up choice, before any network call.
#[derive(Debug)]
pub struct StartupCredential {
    pub identity: HubIdentity,
    /// A one-use token still to be used: for enrollment now (no token) or for
    /// re-enrollment later (the saved token is refused, or enrollment at
    /// start failed).
    pub enrollment: Option<EnrollmentToken>,
}

/// Go's `resolveTokenWithIdentity` up to the enrollment call.
pub fn startup(settings: &Settings, files: &StateFiles) -> StartupCredential {
    let mut enrollment = settings.enrollment.clone();
    if let Some(staged) = &enrollment
        && staged.file.is_some()
        && files.is_consumed(&staged.token)
    {
        log::info!(
            "ignoring the enrollment token file: this token was already used to enroll; remove the file or stage a new token"
        );
        enrollment = None;
    }
    let mut identity = configured_identity(settings);
    if let Some(token) = &settings.api_token {
        identity.token = Some(token.clone());
        return StartupCredential {
            identity,
            enrollment,
        };
    }
    if let Some(token) = files.load_token() {
        identity.token = Some(token);
        restore(files, &mut identity, settings);
        if identity.token.is_some() {
            log::info!("loaded token from {}", files.token.display());
        }
    }
    StartupCredential {
        identity,
        enrollment,
    }
}
