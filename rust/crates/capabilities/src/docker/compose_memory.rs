//! The Compose projects this agent has seen with containers: Go's
//! `composeMemory` (`compose_memory.go`). A project taken down stays listed
//! as `stopped` with no containers while its folder and compose files
//! exist, and is forgotten once they are gone. It is kept in
//! `compose-projects.json` in the agent's state folder, the file and format
//! the Go agent uses, so a host that moves between the agents keeps it.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use labtether_protocol::DockerComposeStack;
use serde::{Deserialize, Serialize};

use super::compose::{Selection, valid_project_name};

pub(crate) const FILE_NAME: &str = "compose-projects.json";
const MAX_BYTES: u64 = 1 << 20;
const MAX_ITEMS: usize = 256;
const STOPPED: &str = "stopped";

#[derive(Serialize, Deserialize)]
struct Remembered {
    name: String,
    dir: String,
    files: Vec<String>,
}

#[derive(Debug, Default)]
pub(crate) struct ComposeMemory {
    path: Option<PathBuf>,
    projects: BTreeMap<String, Selection>,
}

/// Go's `validRememberedSelection`.
fn valid(selection: &Selection) -> bool {
    valid_project_name(&selection.name)
        && selection.dir.starts_with('/')
        && !selection.files.is_empty()
        && selection.files.iter().all(|file| file.starts_with('/'))
}

/// Go's `validateComposeFiles`: the folder is a folder and each file a
/// regular file that opens.
pub(crate) fn files_exist(selection: &Selection) -> bool {
    std::fs::metadata(&selection.dir).is_ok_and(|meta| meta.is_dir())
        && selection.files.iter().all(|file| {
            std::fs::metadata(file).is_ok_and(|meta| meta.is_file())
                && std::fs::File::open(file)
                    .and_then(|opened| opened.metadata())
                    .is_ok_and(|meta| meta.is_file())
        })
}

impl ComposeMemory {
    /// Go's `newComposeMemory`: loads `state_dir`'s file; with no folder it
    /// remembers only while the agent runs.
    pub fn load(state_dir: Option<&Path>) -> Self {
        let mut memory = Self::default();
        let Some(dir) = state_dir else {
            return memory;
        };
        let path = dir.join(FILE_NAME);
        let mut data = Vec::new();
        let read =
            std::fs::File::open(&path).and_then(|file| file.take(MAX_BYTES).read_to_end(&mut data));
        memory.path = Some(path);
        match read {
            // Go's decoder reads the first value and ignores what follows.
            Ok(_) => match serde_json::Deserializer::from_slice(&data)
                .into_iter::<Option<Vec<Remembered>>>()
                .next()
                .unwrap_or(Ok(None))
            {
                Ok(saved) => {
                    for project in saved.unwrap_or_default() {
                        let selection = Selection {
                            name: project.name,
                            dir: project.dir,
                            files: project.files,
                        };
                        if valid(&selection) && memory.projects.len() < MAX_ITEMS {
                            memory.projects.insert(selection.name.clone(), selection);
                        }
                    }
                }
                Err(error) => log::info!("docker: Compose project memory not read: {error}"),
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => log::info!("docker: Compose project memory not read: {error}"),
        }
        memory
    }

    /// Go's `merge`: remembers each live project whose labels name its
    /// files, and adds each remembered project with no containers now as
    /// stopped, while its files exist. An incomplete inventory adds none:
    /// a project past the container limit is not down. Sorted by name.
    pub fn merge(
        &mut self,
        live: Vec<DockerComposeStack>,
        incomplete: bool,
    ) -> Vec<DockerComposeStack> {
        let mut changed = false;
        for stack in &live {
            let selection = Selection {
                name: stack.name.clone(),
                dir: stack.config_dir.clone(),
                files: stack.config_files.clone(),
            };
            if !stack.selection_error.is_empty() || !valid(&selection) {
                continue;
            }
            match self.projects.get(&stack.name) {
                Some(known) if *known == selection => continue,
                None if self.projects.len() >= MAX_ITEMS => continue,
                _ => {}
            }
            self.projects.insert(stack.name.clone(), selection);
            changed = true;
        }
        let mut merged = live;
        if !incomplete {
            let gone: Vec<String> = self
                .projects
                .keys()
                .filter(|name| !merged.iter().any(|stack| &stack.name == *name))
                .cloned()
                .collect();
            for name in gone {
                let selection = &self.projects[&name];
                if !files_exist(selection) {
                    self.projects.remove(&name);
                    changed = true;
                    continue;
                }
                merged.push(DockerComposeStack {
                    name: name.clone(),
                    status: STOPPED.to_owned(),
                    config_dir: selection.dir.clone(),
                    // Go's deprecated folder form for older Hubs.
                    config_file: format!("{}/docker-compose.yml", selection.dir),
                    config_files: selection.files.clone(),
                    containers: Vec::new(),
                    ..DockerComposeStack::default()
                });
            }
        }
        if changed {
            self.save();
        }
        merged.sort_by(|a, b| a.name.cmp(&b.name));
        merged
    }

    /// Go's `saveLocked`: written through a temporary file, mode 0600.
    fn save(&self) {
        let Some(path) = &self.path else {
            return;
        };
        let saved: Vec<Remembered> = self
            .projects
            .values()
            .map(|selection| Remembered {
                name: selection.name.clone(),
                dir: selection.dir.clone(),
                files: selection.files.clone(),
            })
            .collect();
        let Ok(data) = serde_json::to_vec(&saved) else {
            return;
        };
        let temporary = path.with_file_name(format!("{FILE_NAME}.tmp"));
        let written =
            write_private(&temporary, &data).and_then(|()| std::fs::rename(&temporary, path));
        if let Err(error) = written {
            let _ = std::fs::remove_file(&temporary);
            log::info!("docker: Compose project memory not saved: {error}");
        }
    }
}

fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(data)
}
