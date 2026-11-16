//! Compose stacks from container labels: Go's `inferComposeStacks` and
//! `selectionFromLabels` (`compose_selection.go`). A stack is listed even
//! when its labels cannot name its files; `selection_error` then says why.

use std::collections::{BTreeMap, BTreeSet};

use labtether_protocol::DockerComposeStack;

use super::inventory::container_name;
use super::raw;

pub(crate) const PROJECT_LABEL: &str = "com.docker.compose.project";
pub(crate) const DIRECTORY_LABEL: &str = "com.docker.compose.project.working_dir";
pub(crate) const FILES_LABEL: &str = "com.docker.compose.project.config_files";

/// A project's name, folder and compose files.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Selection {
    pub name: String,
    pub dir: String,
    pub files: Vec<String>,
}

/// Go's `composeProjectName`: `^[a-z0-9][a-z0-9_-]*$`.
pub(crate) fn valid_project_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    let plain = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    bytes.next().is_some_and(plain) && bytes.all(|c| plain(c) || c == b'_' || c == b'-')
}

/// Go's `filepath.IsAbs` on Linux, with Go's NUL check.
fn absolute(path: &str) -> bool {
    path.starts_with('/') && !path.contains('\0')
}

/// Go's `selectionFromLabels`: the selection and, when it cannot be used,
/// why (`missing_labels`, `invalid_labels`). The files are kept when only
/// a file name is wrong, as Go keeps them.
pub(crate) fn from_labels(labels: &BTreeMap<String, String>) -> (Selection, &'static str) {
    let label = |key: &str| labels.get(key).cloned().unwrap_or_default();
    let mut selection = Selection {
        name: label(PROJECT_LABEL),
        dir: label(DIRECTORY_LABEL),
        files: Vec::new(),
    };
    let files = label(FILES_LABEL);
    if selection.name.is_empty() || selection.dir.is_empty() || files.is_empty() {
        return (selection, "missing_labels");
    }
    if !valid_project_name(&selection.name) || !absolute(&selection.dir) {
        return (selection, "invalid_labels");
    }
    selection.files = files.split(',').map(str::to_owned).collect();
    if !selection.files.iter().all(|file| absolute(file)) {
        return (selection, "invalid_labels");
    }
    (selection, "")
}

struct Accumulator {
    stack: DockerComposeStack,
    selection: Selection,
    running: usize,
    names: BTreeSet<String>,
}

/// Go's `inferComposeStacks`, sorted by name; with `incomplete` (more
/// containers than the limit) every stack is marked
/// `incomplete_inventory`, as Go's `inferCompleteComposeStacks`.
pub(crate) fn infer(rows: &[raw::Container], incomplete: bool) -> Vec<DockerComposeStack> {
    let mut stacks: BTreeMap<String, Accumulator> = BTreeMap::new();
    for row in rows {
        let Some(project) = row.labels.get(PROJECT_LABEL).filter(|p| !p.is_empty()) else {
            continue;
        };
        let (selection, invalid) = from_labels(&row.labels);
        let acc = match stacks.get_mut(project) {
            Some(acc) => {
                if !invalid.is_empty() || acc.selection != selection {
                    acc.stack.selection_error = "conflicting_labels".to_owned();
                }
                acc
            }
            None => {
                let stack = DockerComposeStack {
                    name: project.clone(),
                    // Go's deprecated folder form for older Hubs; never a
                    // claim that this file exists.
                    config_file: if selection.dir.is_empty() {
                        String::new()
                    } else {
                        format!("{}/docker-compose.yml", selection.dir)
                    },
                    config_dir: selection.dir.clone(),
                    config_files: selection.files.clone(),
                    selection_error: invalid.to_owned(),
                    ..DockerComposeStack::default()
                };
                let fresh = Accumulator {
                    stack,
                    selection,
                    running: 0,
                    names: BTreeSet::new(),
                };
                stacks.entry(project.clone()).or_insert(fresh)
            }
        };
        let name = container_name(&row.names);
        if !name.is_empty() {
            acc.names.insert(name);
        }
        if row.state == "running" {
            acc.running += 1;
        }
    }
    stacks
        .into_values()
        .map(|mut acc| {
            acc.stack.containers = acc.names.into_iter().collect();
            acc.stack.status = format!("running({})", acc.running);
            if incomplete {
                acc.stack.selection_error = "incomplete_inventory".to_owned();
            }
            acc.stack
        })
        .collect()
}
