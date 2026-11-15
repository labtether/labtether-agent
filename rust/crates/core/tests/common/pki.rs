//! Test certificates made at run time, so no key is stored in the repo.

use std::sync::Arc;

use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::TlsAcceptor;

/// A CA and a server certificate for 127.0.0.1 signed by it.
pub struct TestPki {
    pub ca_pem: String,
    pub server_pem: String,
    server_cert: CertificateDer<'static>,
    server_key: Vec<u8>,
}

impl TestPki {
    pub fn new() -> Self {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
        let server_key = KeyPair::generate().unwrap();
        let server = CertificateParams::new(vec!["127.0.0.1".to_owned(), "localhost".to_owned()])
            .unwrap()
            .signed_by(&server_key, &ca)
            .unwrap();
        Self {
            ca_pem: ca.pem(),
            server_pem: server.pem(),
            server_cert: server.der().clone(),
            server_key: server_key.serialize_der(),
        }
    }

    /// A TLS acceptor that presents the server certificate.
    pub fn acceptor(&self) -> TlsAcceptor {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.server_key.clone()));
        let config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![self.server_cert.clone()], key)
            .unwrap();
        TlsAcceptor::from(Arc::new(config))
    }
}
