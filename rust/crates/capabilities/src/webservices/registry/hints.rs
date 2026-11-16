//! How an image name or a hint becomes a registry key: Go's
//! `registry_matchers.go` and the extra aliases of
//! `registry_init_aliases.go`.

/// Go's `registerBaselineHintAliases`, `(key, alias)` in Go's order.
pub(super) const BASELINE_ALIASES: [(&str, &str); 36] = [
    ("nginx-proxy-manager", "npm"),
    ("mqtt", "mosquitto"),
    ("nodered", "node-red"),
    ("codeserver", "code-server"),
    ("jdownloader", "jdownloader-2"),
    ("nzbhydra", "nzbhydra2"),
    ("rtorrent", "rutorrent"),
    ("crafty", "crafty-controller"),
    ("crafty", "crafty-4"),
    ("airsonic", "airsonic-advanced"),
    ("changedetection", "changedetection-io"),
    ("changedetection", "changedetectionio"),
    ("wg-easy", "wg_easy"),
    ("ddns-updater", "ddns"),
    ("cloudflare-ddns", "cloudflare-ddns-updater"),
    ("stirling-pdf", "s-pdf"),
    ("tandoor", "recipes"),
    ("firefly-iii", "fireflyiii"),
    ("woodpecker", "woodpecker-ci"),
    ("zwavejs", "zwave-js-ui"),
    ("zwavejs", "zwave-js"),
    ("wyze-bridge", "wyze"),
    ("double-take", "doubletake"),
    ("guacamole", "apache-guacamole"),
    ("stash", "stashapp"),
    ("jdownloader", "jd"),
    ("jdownloader", "jdownloader2"),
    ("codeserver", "vscode"),
    ("proxmox-backup", "pbs"),
    ("truenas", "truenas-scale"),
    ("truenas", "truenas-core"),
    ("synology", "dsm"),
    ("synology", "diskstation"),
    ("qnap", "qts"),
    ("pfsense", "pf-sense"),
    ("opnsense", "opn-sense"),
];

/// Go's `normalizeDockerImage`: lower case, no digest, no tag (only from
/// the last path part, so a registry port stays), no Docker Hub prefix, no
/// registry host (`localhost`, or a first part holding `.` or `:`), no
/// `library/`.
pub(crate) fn normalize_docker_image(image: &str) -> String {
    let mut image = image.trim().to_lowercase();
    if image.is_empty() {
        return image;
    }
    if let Some(at) = image.find('@') {
        image.truncate(at);
    }
    match image.rfind('/') {
        Some(slash) => {
            if let Some(colon) = image[slash + 1..].rfind(':') {
                image.truncate(slash + 1 + colon);
            }
        }
        None => {
            if let Some(colon) = image.rfind(':') {
                image.truncate(colon);
            }
        }
    }
    let mut image = image.as_str();
    for prefix in [
        "registry-1.docker.io/library/",
        "registry-1.docker.io/",
        "index.docker.io/library/",
        "index.docker.io/",
        "docker.io/library/",
        "docker.io/",
    ] {
        image = image.strip_prefix(prefix).unwrap_or(image);
    }
    if let Some(slash) = image.find('/')
        && slash > 0
    {
        let host = &image[..slash];
        if host == "localhost" || host.contains('.') || host.contains(':') {
            image = &image[slash + 1..];
        }
    }
    image = image.strip_prefix("library/").unwrap_or(image);
    image.trim().to_owned()
}

/// Go's `normalizeServiceHint`: the ASCII letters and digits, lower case.
pub(super) fn normalize_service_hint(raw: &str) -> String {
    raw.trim()
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        .collect()
}

/// Go's `hintCandidates`: the hint, then for a URL its host and the
/// host's first label, the first label, the last path part, and every
/// part between separators.
pub(super) fn hint_candidates(raw: &str) -> Vec<&str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let mut candidates = vec![trimmed];
    if let Some(scheme) = trimmed.find("://") {
        let mut host = &trimmed[scheme + 3..];
        if let Some(slash) = host.find('/') {
            host = &host[..slash];
        }
        if let Some(at) = host.rfind('@')
            && at + 1 < host.len()
        {
            host = &host[at + 1..];
        }
        if let Some(colon) = host.rfind(':')
            && colon > 0
        {
            host = &host[..colon];
        }
        let host = host.trim_matches(['[', ']']);
        if !host.is_empty() {
            candidates.push(host);
            if let Some(dot) = host.find('.')
                && dot > 0
            {
                candidates.push(&host[..dot]);
            }
        }
    }
    if let Some(dot) = trimmed.find('.')
        && dot > 0
    {
        candidates.push(&trimmed[..dot]);
    }
    if let Some(slash) = trimmed.rfind('/')
        && slash + 1 < trimmed.len()
    {
        candidates.push(&trimmed[slash + 1..]);
    }
    let separators = ['/', '\\', ':', '.', '-', '_', ' ', '@'];
    candidates.extend(
        trimmed
            .split(separators)
            .filter(|token| !token.is_empty() && !token.trim().is_empty()),
    );
    candidates
}
