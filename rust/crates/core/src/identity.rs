//! The device key, ported from Go's `device_identity.go` and
//! `internal/agentidentity`. The private key file holds base64 of the 64-byte
//! Go form (seed then public key); a 32-byte seed is also read.

use std::io;
use std::path::{Path, PathBuf};

use data_encoding::{BASE32_NOPAD, BASE64, HEXLOWER};
use ed25519_dalek::{Signer, SigningKey};
use labtether_agent_config::Settings;
use labtether_agent_config::files::{self, MAX_DEVICE_KEY_FILE_BYTES};
use sha2::{Digest, Sha256};

use crate::fsutil::{self, PRIVATE, PUBLIC};

pub const KEY_ALGORITHM: &str = "ed25519";

/// Why the device key could not be loaded or created.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("cannot read device key {path}: {source}")]
    Read {
        path: PathBuf,
        source: files::ReadError,
    },
    #[error("device key {0} is not valid base64")]
    Encoding(PathBuf),
    #[error("device key {path} has an unexpected size of {size} bytes")]
    Size { path: PathBuf, size: usize },
    #[error("device key {path} does not match its own public key")]
    Mismatch { path: PathBuf },
    #[error("no system randomness for a new device key")]
    Random,
    #[error("cannot write {path}: {source}")]
    Write { path: PathBuf, source: io::Error },
}

/// The agent's ed25519 device key and the values derived from it.
#[derive(Clone)]
pub struct DeviceIdentity {
    key: SigningKey,
    pub public_key_base64: String,
    pub fingerprint: String,
}

impl std::fmt::Debug for DeviceIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeviceIdentity")
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

impl DeviceIdentity {
    fn from_key(key: SigningKey) -> Self {
        let public = key.verifying_key().to_bytes();
        Self {
            public_key_base64: BASE64.encode(&public),
            fingerprint: fingerprint(&public),
            key,
        }
    }

    pub fn key_algorithm(&self) -> &'static str {
        KEY_ALGORITHM
    }

    /// Signs `payload` and returns standard base64, as the Hub expects.
    pub fn sign_base64(&self, payload: &[u8]) -> String {
        BASE64.encode(&self.key.sign(payload).to_bytes())
    }

    /// The raw public key, for tests that verify signatures.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }
}

/// `LT-` and base32 (no padding) of SHA-256 of the public key, in groups of 4.
pub fn fingerprint(public_key: &[u8]) -> String {
    let encoded = BASE32_NOPAD.encode(&Sha256::digest(public_key));
    let groups: Vec<&str> = encoded
        .as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or_default())
        .collect();
    format!("LT-{}", groups.join("-"))
}

/// Go's `BuildEnrollmentProofPayload` (pending enrollment over the socket).
pub fn enrollment_proof_payload(connection_id: &str, nonce: &str, fingerprint: &str) -> Vec<u8> {
    format!(
        "labtether-enrollment-proof|{}|{}|{}",
        connection_id.trim(),
        nonce.trim(),
        fingerprint.trim()
    )
    .into_bytes()
}

/// Go's `BuildTokenEnrollmentProofPayload` (v1, bound to the host name) and
/// `BuildTokenEnrollmentProofPayloadV2` (v2, bound to the Hub's asset ID).
pub fn token_proof_payload(
    version: ProofVersion,
    subject: &str,
    token: &str,
    fingerprint: &str,
) -> Vec<u8> {
    let token_hash = HEXLOWER.encode(&Sha256::digest(token.trim().as_bytes()));
    let prefix = match version {
        ProofVersion::V1 => "labtether-token-enrollment-proof-v1",
        ProofVersion::V2 => "labtether-token-enrollment-proof-v2",
    };
    format!(
        "{prefix}|{}|{token_hash}|{}",
        subject.trim(),
        fingerprint.trim()
    )
    .into_bytes()
}

/// Which token-enrollment proof the request carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofVersion {
    V1,
    V2,
}

impl ProofVersion {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::V1 => "v1",
            Self::V2 => "v2",
        }
    }
}

fn load(path: &Path) -> Result<DeviceIdentity, IdentityError> {
    let raw = files::read_trimmed(path, MAX_DEVICE_KEY_FILE_BYTES).map_err(|source| {
        IdentityError::Read {
            path: path.to_owned(),
            source,
        }
    })?;
    let decoded = BASE64
        .decode(raw.as_bytes())
        .map_err(|_| IdentityError::Encoding(path.to_owned()))?;
    let key = match decoded.len() {
        32 => SigningKey::from_bytes(decoded.as_slice().try_into().unwrap_or(&[0; 32])),
        64 => {
            let bytes: &[u8; 64] = decoded.as_slice().try_into().unwrap_or(&[0; 64]);
            SigningKey::from_keypair_bytes(bytes).map_err(|_| IdentityError::Mismatch {
                path: path.to_owned(),
            })?
        }
        size => {
            return Err(IdentityError::Size {
                path: path.to_owned(),
                size,
            });
        }
    };
    Ok(DeviceIdentity::from_key(key))
}

fn write(path: &Path, data: &[u8], mode: u32) -> Result<(), IdentityError> {
    fsutil::write_atomic(path, data, mode).map_err(|source| IdentityError::Write {
        path: path.to_owned(),
        source,
    })
}

fn write_public_files(settings: &Settings, identity: &DeviceIdentity) -> Result<(), IdentityError> {
    let public = format!("{}\n", identity.public_key_base64);
    write(&settings.device_public_key_file, public.as_bytes(), PUBLIC)?;
    let fingerprint = format!("{}\n", identity.fingerprint);
    write(
        &settings.device_fingerprint_file,
        fingerprint.as_bytes(),
        PUBLIC,
    )
}

/// Go's `ensureDeviceIdentity`: load the key, or create and save one when
/// none exists. An existing key is never replaced, even when unreadable.
pub fn ensure(settings: &Settings) -> Result<DeviceIdentity, IdentityError> {
    match load(&settings.device_key_file) {
        Ok(identity) => {
            if let Err(error) = write_public_files(settings, &identity) {
                log::warn!("could not refresh the device public key files: {error}");
            }
            Ok(identity)
        }
        Err(IdentityError::Read { source, .. }) if source.is_not_found() => {
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).map_err(|_| IdentityError::Random)?;
            let identity = DeviceIdentity::from_key(SigningKey::from_bytes(&seed));
            let private = format!("{}\n", BASE64.encode(&identity.key.to_keypair_bytes()));
            write(&settings.device_key_file, private.as_bytes(), PRIVATE)?;
            write_public_files(settings, &identity)?;
            Ok(identity)
        }
        Err(error) => Err(error),
    }
}
