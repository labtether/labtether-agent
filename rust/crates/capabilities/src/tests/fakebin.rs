//! Fake programs for the pages that start one: a folder that is the whole
//! `PATH` of a [`CommandPolicy`], holding small `/bin/sh` scripts named
//! like the real tools. Each script writes its arguments to
//! `<name>.calls` and its environment to `<name>.env`, then does what the
//! test asked. The real page code runs them through `CommandPolicy::run`.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, MutexGuard};

use labtether_agent_config::{CommandSecuritySettings, Environment};
use labtether_agent_security::CommandPolicy;

/// Held by every test that writes or starts a program. Without it, a child
/// forked by one test thread can still hold another thread's script open
/// for writing when that script is started, and the start fails with
/// `ETXTBSY` (seen once in three full test runs on the lab VM).
pub(crate) fn serial() -> MutexGuard<'static, ()> {
    static SERIAL: Mutex<()> = Mutex::new(());
    SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub(crate) struct FakeBin {
    pub dir: PathBuf,
}

impl FakeBin {
    pub fn new() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "lt-fakebin-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).unwrap();
        Self { dir }
    }

    /// A program `name` whose shell `body` runs after the call is logged.
    /// `$D` is this folder.
    pub fn program(&self, name: &str, body: &str) -> &Self {
        let path = self.dir.join(name);
        let script = format!(
            "#!/bin/sh\nD='{}'\necho \"$*\" >> \"$D/{name}.calls\"\n/usr/bin/env > \"$D/{name}.env\"\n{body}\n",
            self.dir.display()
        );
        fs::write(&path, script).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        self
    }

    /// A file the scripts can print with `/bin/cat "$D/<name>"`.
    pub fn file(&self, name: &str, bytes: &[u8]) -> &Self {
        fs::write(self.dir.join(name), bytes).unwrap();
        self
    }

    /// The argument lines `name` was called with, or `None` if it never ran.
    pub fn calls(&self, name: &str) -> Option<Vec<String>> {
        let text = fs::read_to_string(self.dir.join(format!("{name}.calls"))).ok()?;
        Some(text.lines().map(str::to_owned).collect())
    }

    /// The environment `name` last ran with, sorted.
    pub fn env(&self, name: &str) -> Vec<String> {
        let text = fs::read_to_string(self.dir.join(format!("{name}.env"))).unwrap();
        let mut lines: Vec<String> = text
            .lines()
            .filter(|l| !l.starts_with("PWD=") && !l.starts_with("SHLVL=") && !l.starts_with("_="))
            .map(str::to_owned)
            .collect();
        lines.sort();
        lines
    }

    /// The agent environment the policy is built from: this folder as the
    /// only `PATH`, a UTF-8 locale, and a variable no child may see.
    pub fn agent_env(&self) -> Environment {
        Environment::from_pairs([
            ("PATH", self.dir.display().to_string()),
            ("HOME", "/home/demo".to_owned()),
            ("LANG", "de_DE.UTF-8".to_owned()),
            ("LC_ALL", "de_DE.UTF-8".to_owned()),
            (
                "LABTETHER_SECRET_FOR_TEST",
                "must-not-reach-children".to_owned(),
            ),
        ])
    }

    /// Go's default command rules over [`FakeBin::agent_env`], with
    /// `blocked` on the blocked list.
    pub fn policy(&self, blocked: &[&str]) -> CommandPolicy {
        let mut settings: CommandSecuritySettings = crate::tests::settings().command_security;
        settings.exec_blocked_binaries = blocked.iter().map(|b| (*b).to_owned()).collect();
        CommandPolicy::new(&settings, &self.agent_env())
    }
}

impl Drop for FakeBin {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}
