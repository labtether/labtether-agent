//! Trust for connections to the Hub, ported from Go's `tls.go` and
//! `tls_ca_only.go`:
//!
//! - default: the system roots plus the configured CA file;
//! - CA-only (`LABTETHER_TLS_CA_ONLY`): the CA file alone, and start fails
//!   when it is unusable, so a typo never falls back to the system roots;
//! - skip-verify is opt-in, and a configured CA overrides it.

use std::path::Path;
use std::sync::Arc;

use labtether_agent_config::TlsSettings;
use labtether_agent_config::files::{self, MAX_CA_FILE_BYTES};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};

/// Why a TLS setup was refused.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error(
        "LABTETHER_TLS_CA_ONLY is on but no CA file is set: set LABTETHER_TLS_CA_FILE or turn LABTETHER_TLS_CA_ONLY off"
    )]
    CaOnlyWithoutFile,
    #[error("LABTETHER_TLS_CA_ONLY is on but the CA file {path} cannot be read: {source}")]
    CaOnlyUnreadable {
        path: String,
        source: files::ReadError,
    },
    #[error("LABTETHER_TLS_CA_ONLY is on but the CA file {0} holds no certificate")]
    CaOnlyEmpty(String),
    #[error("TLS setup failed: {0}")]
    Rustls(#[from] rustls::Error),
}

/// What the agent will check on the Hub's certificate. Used for the one
/// start-up log line and in tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustMode {
    SystemRoots,
    SystemRootsAndCa,
    CaOnly,
    SkipVerify,
}

/// Decides the trust mode from the settings, without reading files.
pub fn trust_mode(tls: &TlsSettings) -> TrustMode {
    match (tls.ca_only, &tls.ca_file, tls.skip_verify) {
        (true, _, _) => TrustMode::CaOnly,
        (false, Some(_), _) => TrustMode::SystemRootsAndCa,
        (false, None, true) => TrustMode::SkipVerify,
        (false, None, false) => TrustMode::SystemRoots,
    }
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn read_pem_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, files::ReadError> {
    let data = files::read_bounded(path, MAX_CA_FILE_BYTES)?;
    Ok(CertificateDer::pem_slice_iter(&data)
        .filter_map(Result::ok)
        .collect())
}

fn ca_only_roots(tls: &TlsSettings) -> Result<RootCertStore, TlsError> {
    let path = tls.ca_file.as_deref().ok_or(TlsError::CaOnlyWithoutFile)?;
    let shown = path.display().to_string();
    let certs = read_pem_certs(path).map_err(|source| TlsError::CaOnlyUnreadable {
        path: shown.clone(),
        source,
    })?;
    let mut roots = RootCertStore::empty();
    let (added, _) = roots.add_parsable_certificates(certs);
    if added == 0 {
        return Err(TlsError::CaOnlyEmpty(shown));
    }
    Ok(roots)
}

/// The start check: with CA-only on, the CA file must be usable.
pub fn validate(tls: &TlsSettings) -> Result<(), TlsError> {
    if tls.ca_only {
        ca_only_roots(tls)?;
    }
    Ok(())
}

fn system_roots_and_ca(tls: &TlsSettings) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    if !native.errors.is_empty() {
        log::warn!(
            "some system CA certificates could not be loaded ({} errors)",
            native.errors.len()
        );
    }
    roots.add_parsable_certificates(native.certs);
    if let Some(path) = tls.ca_file.as_deref() {
        match read_pem_certs(path) {
            Ok(certs) => {
                let (added, _) = roots.add_parsable_certificates(certs);
                if added == 0 {
                    log::warn!("no valid certificates found in {}", path.display());
                }
            }
            Err(error) => log::warn!("cannot read TLS CA file {}: {error}", path.display()),
        }
    }
    roots
}

/// Builds the client configuration used for both enrollment and the
/// WebSocket. TLS 1.2 is the lowest version, as in Go.
pub fn client_config(tls: &TlsSettings) -> Result<Arc<ClientConfig>, TlsError> {
    let provider = provider();
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?;
    let config = match trust_mode(tls) {
        TrustMode::CaOnly => builder
            .with_root_certificates(ca_only_roots(tls)?)
            .with_no_client_auth(),
        TrustMode::SkipVerify => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate {
                algorithms: provider.signature_verification_algorithms,
            }))
            .with_no_client_auth(),
        TrustMode::SystemRoots | TrustMode::SystemRootsAndCa => builder
            .with_root_certificates(system_roots_and_ca(tls))
            .with_no_client_auth(),
    };
    Ok(Arc::new(config))
}

/// Skip-verify: accepts any certificate but still checks that the server
/// holds the key for the one it sent, as Go's `InsecureSkipVerify` does.
#[derive(Debug)]
struct AcceptAnyCertificate {
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for AcceptAnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// Go's `validateCACertPEM`: the Hub's enrollment answer may carry its CA,
/// which is saved only when it is a certificate with the CA flag set.
pub fn is_ca_certificate_pem(pem: &str) -> bool {
    let mut certs = CertificateDer::pem_slice_iter(pem.as_bytes());
    match certs.next() {
        Some(Ok(cert)) => crate::der::basic_constraints_ca(cert.as_ref()).unwrap_or(false),
        _ => false,
    }
}
