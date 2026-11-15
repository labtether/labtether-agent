//! Go's `child_env.go`: a started command inherits only the variables it
//! needs to find programs, temporary folders, the user profile and the
//! desktop session. Names are not guessed: a new or uncommon variable is
//! dropped, so credentials cannot leak into a command.

use labtether_agent_config::Environment;

use crate::gotext::upper;
use crate::lists::ALLOWED_CHILD_ENV;

/// Go's `isAllowedChildEnvKey`: a listed name or `LC_*`, ignoring case and
/// surrounding space.
pub fn is_allowed_child_env_key(key: &str) -> bool {
    let name = upper(key.trim());
    ALLOWED_CHILD_ENV.contains(&name.as_str()) || name.starts_with("LC_")
}

/// Go's `SanitizedChildEnv`, from the environment captured at start rather
/// than the live process environment. Values are kept exactly; the result
/// is sorted by name so every command gets the same order.
pub fn sanitized_child_env(env: &Environment) -> Vec<(String, String)> {
    let mut kept: Vec<(String, String)> = env
        .raw_pairs()
        .filter(|(key, _)| is_allowed_child_env_key(key))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect();
    kept.sort();
    kept
}
