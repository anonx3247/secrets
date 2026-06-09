//! In-memory store of captured secrets.
//!
//! Secrets live here and nowhere else the agent can reach: captured on demand,
//! held only until their TTL expires, and never serialized back over the wire.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use sx_proto::CaptureInfo;

/// One captured `.env` source and the values it provided.
struct Capture {
    /// Canonical absolute path the values came from (display/identity only).
    source: String,
    values: HashMap<String, String>,
    expires_at: Instant,
}

/// All active captures. Not `Clone`/`Serialize` on purpose.
#[derive(Default)]
pub struct State {
    captures: Vec<Capture>,
}

impl State {
    /// Drop any captures whose TTL has elapsed.
    fn purge_expired(&mut self) {
        let now = Instant::now();
        self.captures.retain(|c| c.expires_at > now);
    }

    /// Insert (or replace) the capture for `source`, expiring after `ttl`.
    pub fn add(&mut self, source: String, values: HashMap<String, String>, ttl: Duration) {
        self.purge_expired();
        self.captures.retain(|c| c.source != source);
        self.captures.push(Capture {
            source,
            values,
            expires_at: Instant::now() + ttl,
        });
    }

    /// Remove a single source's capture, or all of them when `path` is `None`.
    /// Returns how many captures were removed.
    pub fn clear(&mut self, path: Option<&str>) -> usize {
        let before = self.captures.len();
        match path {
            Some(p) => self.captures.retain(|c| c.source != p),
            None => self.captures.clear(),
        }
        before - self.captures.len()
    }

    /// Return the values of a still-live grant for `source`, or `None` if it is
    /// not granted (or its TTL has elapsed). Used to skip re-prompting within
    /// the grant window.
    pub fn live_values(&mut self, source: &str) -> Option<Vec<(String, String)>> {
        self.purge_expired();
        self.captures.iter().find(|c| c.source == source).map(|c| {
            c.values
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        })
    }

    /// Snapshot of active captures, safe to hand to the agent (names only).
    pub fn info(&mut self) -> Vec<CaptureInfo> {
        self.purge_expired();
        let now = Instant::now();
        self.captures
            .iter()
            .map(|c| {
                let mut names: Vec<String> = c.values.keys().cloned().collect();
                names.sort();
                CaptureInfo {
                    source: c.source.clone(),
                    names,
                    expires_in_secs: c.expires_at.saturating_duration_since(now).as_secs(),
                }
            })
            .collect()
    }
}
