//! Go's `path/filepath` functions on Unix, for ported rules whose results
//! depend on them exactly: `Clean`, `Base`, `Dir`, `Join` and `IsAbs`.
//! They work on text only and never touch the filesystem.

/// Go's `filepath.IsAbs` on Unix.
pub fn is_abs(path: &str) -> bool {
    path.starts_with('/')
}

/// Go's `filepath.Clean` on Unix: one slash between names, no `.` names,
/// `..` resolved against the name before it, `..` at the root dropped, and
/// `.` for an empty result.
pub fn clean(path: &str) -> String {
    if path.is_empty() {
        return ".".to_owned();
    }
    let rooted = is_abs(path);
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => match parts.last() {
                Some(&last) if last != ".." => {
                    parts.pop();
                }
                _ if rooted => {}
                _ => parts.push(".."),
            },
            name => parts.push(name),
        }
    }
    let joined = parts.join("/");
    match (rooted, joined.is_empty()) {
        (true, _) => format!("/{joined}"),
        (false, true) => ".".to_owned(),
        (false, false) => joined,
    }
}

/// Go's `filepath.Base` on Unix: the last name after trailing slashes are
/// removed, `.` for an empty path and `/` for a path of slashes.
pub fn base(path: &str) -> String {
    if path.is_empty() {
        return ".".to_owned();
    }
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return "/".to_owned();
    }
    match trimmed.rfind('/') {
        Some(index) => trimmed[index + 1..].to_owned(),
        None => trimmed.to_owned(),
    }
}

/// Go's `filepath.Dir` on Unix: everything before the last slash, cleaned.
pub fn dir(path: &str) -> String {
    match path.rfind('/') {
        Some(index) => clean(&path[..=index]),
        None => clean(""),
    }
}

/// Go's `filepath.Join` on Unix: non-empty parts joined by `/`, cleaned.
pub fn join(parts: &[&str]) -> String {
    let kept: Vec<&str> = parts.iter().copied().filter(|p| !p.is_empty()).collect();
    if kept.is_empty() {
        return String::new();
    }
    clean(&kept.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fault: a protected path such as /etc//shadow or /etc/../etc/shadow is
    // not recognised because the text differs from Go's cleaned form.
    #[test]
    fn clean_base_and_dir_match_go() {
        let cleaned = [
            ("", "."),
            ("/", "/"),
            ("//etc//shadow/", "/etc/shadow"),
            ("/etc/../etc/./shadow", "/etc/shadow"),
            ("/..", "/"),
            ("/../a", "/a"),
            ("a/../..", ".."),
            ("../../a", "../../a"),
            ("a/b/../../c", "c"),
            ("./", "."),
        ];
        for (input, want) in cleaned {
            assert_eq!(clean(input), want, "clean({input:?})");
        }
        let bases = [
            ("", "."),
            ("/", "/"),
            ("///", "/"),
            ("/usr/bin/", "bin"),
            ("a", "a"),
        ];
        for (input, want) in bases {
            assert_eq!(base(input), want, "base({input:?})");
        }
        let dirs = [
            ("", "."),
            ("/", "/"),
            ("a", "."),
            ("/a/b/", "/a/b"),
            ("/a//b", "/a"),
        ];
        for (input, want) in dirs {
            assert_eq!(dir(input), want, "dir({input:?})");
        }
        assert_eq!(join(&["/home/demo", ".labtether"]), "/home/demo/.labtether");
        assert_eq!(join(&["", ""]), "");
    }
}
