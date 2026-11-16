//! Alerts the Hub pushes with `alert.notify`, kept for the local status
//! page. Ported from the Go agent's `handleAlertNotify` and `pushAlert`
//! (`command_handler.go`, `local_status.go`): an alert with a known ID is
//! replaced in place, a new one is added at the end, and only the newest
//! 20 are kept.
//!
//! The timestamp is kept as the Hub sent it; the local API reads it with
//! Go's RFC 3339 rules when it writes the page (Go reads it on arrival; the
//! page is the same).

use std::sync::Mutex;

use labtether_protocol::AlertNotifyData;

/// Go's `maxCachedAlerts`.
pub const MAX_ALERTS: usize = 20;

/// One alert as the Hub sent it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alert {
    pub id: String,
    pub severity: String,
    pub title: String,
    pub summary: String,
    pub state: String,
    /// RFC 3339 text from the Hub, unread.
    pub timestamp: String,
}

impl From<AlertNotifyData> for Alert {
    fn from(data: AlertNotifyData) -> Self {
        Self {
            id: data.id,
            severity: data.severity,
            title: data.title,
            summary: data.summary,
            state: data.state,
            timestamp: data.timestamp,
        }
    }
}

/// The alert list, oldest first.
#[derive(Debug, Default)]
pub struct AlertCache(Mutex<Vec<Alert>>);

impl AlertCache {
    /// Go's `pushAlert`.
    pub fn push(&self, alert: Alert) {
        let mut alerts = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(existing) = alerts.iter_mut().find(|a| a.id == alert.id) {
            *existing = alert;
            return;
        }
        alerts.push(alert);
        if alerts.len() > MAX_ALERTS {
            let extra = alerts.len() - MAX_ALERTS;
            alerts.drain(..extra);
        }
    }

    /// A copy of the list.
    pub fn snapshot(&self) -> Vec<Alert> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::{Alert, AlertCache, MAX_ALERTS};

    fn alert(id: usize, state: &str) -> Alert {
        Alert {
            id: format!("alr-{id}"),
            severity: "high".into(),
            title: "Disk usage above 90%".into(),
            summary: "/srv/media is 93% full".into(),
            state: state.into(),
            timestamp: "2026-11-14T09:12:40Z".into(),
        }
    }

    // Faults: the cap drops the newest alerts instead of the oldest, a
    // resolved alert is added twice instead of replacing the firing one,
    // or the list grows past Go's 20.
    #[test]
    fn cache_keeps_the_newest_twenty_and_replaces_by_id() {
        let cache = AlertCache::default();
        for id in 0..22 {
            cache.push(alert(id, "firing"));
        }
        cache.push(alert(5, "resolved"));
        let ids: Vec<String> = cache.snapshot().iter().map(|a| a.id.clone()).collect();
        let want: Vec<String> = (2..22).map(|id| format!("alr-{id}")).collect();
        assert_eq!(ids, want);
        assert_eq!(cache.snapshot().len(), MAX_ALERTS);
        assert_eq!(cache.snapshot()[3].state, "resolved");
    }
}
