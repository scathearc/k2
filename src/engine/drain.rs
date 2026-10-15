//! Zero-allocation response body draining.
//!
//! Inbound frames are read straight off the stream and discarded into a
//! fixed thread-local 8KB scratch block: no deserialization, no heap
//! churn, no per-byte string conversion. Only byte counts survive.

use futures::StreamExt;
use std::cell::RefCell;

const SCRATCH_BYTES: usize = 8 * 1024;

thread_local! {
    static SCRATCH: RefCell<Box<[u8; SCRATCH_BYTES]>> = RefCell::new(Box::new([0u8; SCRATCH_BYTES]));
}

/// Drain a wreq response body to /dev/null. Returns (bytes_in, error-kind).
pub async fn drain(resp: wreq::Response) -> (u64, Option<crate::error::ErrorKind>) {
    let mut stream = resp.bytes_stream();
    let mut total: u64 = 0;
    loop {
        match stream.next().await {
            None => return (total, None),
            Some(Ok(chunk)) => {
                // Touch the bytes into the fixed thread-local scratch block.
                let len = chunk.len();
                let data = &chunk[..];
                SCRATCH.with(|cell| {
                    let mut borrow = cell.borrow_mut();
                    let slice: &mut [u8] = &mut borrow[..];
                    let mut off = 0usize;
                    while off < len {
                        let n = (len - off).min(slice.len());
                        slice[..n].copy_from_slice(&data[off..off + n]);
                        off += n;
                    }
                });
                total = total.saturating_add(len as u64);
            }
            Some(Err(e)) => {
                let kind = if e.is_timeout() {
                    crate::error::ErrorKind::Timeout
                } else if e.is_connect() {
                    crate::error::ErrorKind::Connect
                } else if e.is_decode() || e.is_body() {
                    crate::error::ErrorKind::Reset
                } else {
                    crate::error::ErrorKind::Io
                };
                return (total, Some(kind));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    // Body drain semantics are covered by the engine integration tests via a
    // live harness server (see tests/engine.rs).
}
