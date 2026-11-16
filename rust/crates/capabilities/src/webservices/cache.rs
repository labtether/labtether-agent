//! The recognition probes' results kept between cycles: Go's
//! `fingerprintCache` and `compatCache` (`fingerprinting.go`, `compat.go`).
//! A result is used while the clock is before its expiry and dropped once
//! read after it. Over 1,024 entries the expired ones go, then those that
//! expire first, until 1,024 are left (Go picks among equal expiry times
//! in its map's random order; this picks the smallest key).

use std::collections::HashMap;
use std::time::SystemTime;

/// Go's `maxFingerprintCacheEntries` and `maxCompatCacheEntries`.
pub(crate) const MAX_ENTRIES: usize = 1024;

#[derive(Debug)]
pub(crate) struct Expiring<V> {
    entries: HashMap<String, (V, SystemTime)>,
}

impl<V> Default for Expiring<V> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }
}

impl<V: Clone> Expiring<V> {
    /// The kept result while `now` is before its expiry; an expired one is
    /// dropped.
    pub fn get(&mut self, key: &str, now: SystemTime) -> Option<V> {
        let (value, expires) = self.entries.get(key)?;
        if now < *expires {
            return Some(value.clone());
        }
        self.entries.remove(key);
        None
    }

    /// Keeps `value` until `expires`, then prunes as Go does.
    pub fn put(&mut self, key: String, value: V, expires: SystemTime, now: SystemTime) {
        self.entries.insert(key, (value, expires));
        if self.entries.len() <= MAX_ENTRIES {
            return;
        }
        self.entries.retain(|_, (_, expires)| now <= *expires);
        while self.entries.len() > MAX_ENTRIES {
            let Some(first) = self
                .entries
                .iter()
                .min_by(|a, b| (a.1.1, a.0).cmp(&(b.1.1, b.0)))
                .map(|(key, _)| key.clone())
            else {
                return;
            };
            self.entries.remove(&first);
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub fn contains(&self, key: &str) -> bool {
        self.entries.contains_key(key)
    }
}
