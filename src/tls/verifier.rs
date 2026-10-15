//! Custom certificate verification bypass (`rustls::client::danger::ServerCertVerifier`).
//!
//! Eliminates certificate-chain validation, RSA/ECDSA signature verification,
//! and OCSP/CRL lookups from client-side handshake CPU cost. Used on the
//! HTTP/3 (quinn/rustls) path; the wreq path injects the equivalent via
//! `tls_cert_verification(false)`.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

/// Always-accept verifier. Only ever used where operators asked for the
/// validation bypass (default) — see `--tls-verify`.
#[derive(Debug)]
pub struct NoVerify {
    schemes: WebPkiSupportedAlgorithms,
}

impl NoVerify {
    pub fn new(provider: &CryptoProvider) -> Self {
        Self {
            schemes: provider.signature_verification_algorithms,
        }
    }
    pub fn boxed(provider: &CryptoProvider) -> std::sync::Arc<dyn ServerCertVerifier> {
        std::sync::Arc::new(Self::new(provider))
    }
}

impl ServerCertVerifier for NoVerify {
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
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        let v = self.schemes.supported_schemes();
        if v.is_empty() {
            // Bypass accepts all; but rustls requires at least one entry to
            // negotiate the ClientHello signature_algorithms extension.
            vec![SignatureScheme::RSA_PSS_SHA256]
        } else {
            v
        }
    }
}
