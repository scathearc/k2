//! User-Agent, ALPN, and extension-order matching profiles (Identity Engine).
//!
//! wreq's emulation presets carry coherent TLS + HTTP/2 + header semantics for
//! modern browsers. `Random` draws a market-share-weighted coherent profile
//! per request so each fresh TLS connection carries a legitimate, browser-grade
//! ClientHello (JA3/JA4 parity) — while BoringSSL keeps the client-side TLS
//! execution cost low (X25519, TLS 1.3, session resumption by default).

use crate::config::Fidelity;
use wreq_util::{Emulation, Profile};

/// Map a fidelity setting onto a concrete emulation preset.
///
/// `None` means "no emulation" (plain BoringSSL defaults — the leanest path).
pub fn pick(f: Fidelity) -> Option<Emulation> {
    match f {
        Fidelity::Chrome => Some(Emulation::builder().profile(Profile::Chrome149).build()),
        Fidelity::Firefox => Some(Emulation::builder().profile(Profile::Firefox151).build()),
        Fidelity::Safari => Some(Emulation::builder().profile(Profile::Safari26_4).build()),
        Fidelity::Edge => Some(Emulation::builder().profile(Profile::Edge148).build()),
        Fidelity::Opera => Some(Emulation::builder().profile(Profile::Opera131).build()),
        Fidelity::Okhttp => Some(Emulation::builder().profile(Profile::OkHttp5).build()),
        Fidelity::Random => Some(Emulation::weighted_random()),
        Fidelity::None => None,
    }
}

/// Static description for telemetry display.
pub fn describe(f: Fidelity) -> &'static str {
    match f {
        Fidelity::Chrome => "chrome-149",
        Fidelity::Firefox => "firefox-151",
        Fidelity::Safari => "safari-26.4",
        Fidelity::Edge => "edge-148",
        Fidelity::Opera => "opera-131",
        Fidelity::Okhttp => "okhttp-5",
        Fidelity::Random => "weighted-random-per-request",
        Fidelity::None => "plain",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_families_resolve() {
        for f in [
            Fidelity::Chrome,
            Fidelity::Firefox,
            Fidelity::Safari,
            Fidelity::Edge,
            Fidelity::Opera,
            Fidelity::Okhttp,
            Fidelity::Random,
        ] {
            assert!(pick(f).is_some());
        }
        assert!(pick(Fidelity::None).is_none());
    }
}
