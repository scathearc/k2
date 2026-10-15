//! HTTP/2 multiplexed path. Consolidated by design: all H2 traffic flows
//! through the wreq/BoringSSL engine (see `engine::client`); this module keeps
//! the spec'd file layout and hosts H2-specific tuning knobs.

use crate::config::HttpVersion;

/// Whether this protocol path should handle the given request.
pub fn handles(v: HttpVersion) -> bool {
    matches!(v, HttpVersion::Auto | HttpVersion::H2)
}
