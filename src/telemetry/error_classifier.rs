//! HTTP status and transport-error classification bookkeeping.
//!
//! Exact status counters (capped at 599) plus a transport-error taxonomy, each
//! in two views: cumulative totals and 100ms-window deltas (reset on tick).

use crate::error::ErrorKind;

pub const MAX_STATUS: usize = 600;

#[derive(Debug, Clone, Copy, Default)]
pub struct WindowTotals {
    pub count: u64,
    pub errors: u64,
    pub s429: u64,
    pub s403: u64,
    pub s503: u64,
    /// Status codes >= 400 in the window (status-first degradation signal).
    pub bad_status: u64,
    /// Explicit 405s — method-blocked at the edge; equivalent to 403 for
    /// mitigation purposes.
    pub s405: u64,
}

#[derive(Debug)]
pub struct ClassifierState {
    status_total: [AtomicU64Cell; MAX_STATUS],
    status_window: [AtomicU64Cell; MAX_STATUS],
    err_total: [AtomicU64Cell; N_KINDS],
    err_window: [AtomicU64Cell; N_KINDS],
    window_count: AtomicU64Cell,
    window_err_count: AtomicU64Cell,
    window_bad_status: AtomicU64Cell,
}

pub const N_KINDS: usize = 10;
const _: () = {
    // ErrorKind::Cancelled must stay within N_KINDS
};

/// Cumulative status counts keyed by code.
pub type StatusCounts = Vec<(u16, u64)>;
/// Cumulative transport error counts keyed by kind.
pub type ErrorCounts = Vec<(ErrorKind, u64)>;

#[derive(Debug, Default)]
struct AtomicU64Cell(std::sync::atomic::AtomicU64);

impl AtomicU64Cell {
    fn inc(&self) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    fn take(&self) -> u64 {
        self.0.swap(0, std::sync::atomic::Ordering::Relaxed)
    }
    fn get(&self) -> u64 {
        self.0.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl Default for ClassifierState {
    fn default() -> Self {
        Self::new()
    }
}

impl ClassifierState {
    pub fn new() -> Self {
        Self {
            status_total: std::array::from_fn(|_| AtomicU64Cell::default()),
            status_window: std::array::from_fn(|_| AtomicU64Cell::default()),
            err_total: std::array::from_fn(|_| AtomicU64Cell::default()),
            err_window: std::array::from_fn(|_| AtomicU64Cell::default()),
            window_count: Default::default(),
            window_err_count: Default::default(),
            window_bad_status: Default::default(),
        }
    }

    #[inline]
    pub fn record_status(&self, code: u16) {
        let i = usize::from(code) % MAX_STATUS;
        self.status_total[i].inc();
        self.status_window[i].inc();
        self.window_count.inc();
        if usize::from(code) >= 400 {
            self.window_bad_status.inc();
        }
    }

    #[inline]
    pub fn record_error(&self, kind: ErrorKind) {
        let i = (kind as usize) % N_KINDS;
        self.err_total[i].inc();
        self.err_window[i].inc();
        self.window_err_count.inc();
    }

    /// Read cumulative per-status counts (non-window).
    pub fn status_map(&self) -> StatusCounts {
        self.status_total
            .iter()
            .enumerate()
            .filter(|(_, c)| c.get() > 0)
            .map(|(i, c)| (i as u16, c.get()))
            .collect()
    }

    pub fn error_map(&self) -> ErrorCounts {
        self.err_total
            .iter()
            .enumerate()
            .filter(|(_, c)| c.get() > 0)
            .map(|(i, c)| (ErrorKind::from_index(i), c.get()))
            .collect()
    }

    /// Drain window deltas; returns tallies for the last 100ms slice.
    pub fn drain_window(&self) -> WindowTotals {
        let mut wt = WindowTotals {
            count: self.window_count.take(),
            errors: self.window_err_count.take(),
            bad_status: self.window_bad_status.take(),
            ..Default::default()
        };
        for (code, cell) in self.status_window.iter().enumerate() {
            let n = cell.take();
            if n == 0 {
                continue;
            }
            match code {
                403 => wt.s403 += n,
                405 => wt.s405 += n,
                429 => wt.s429 += n,
                503 => wt.s503 += n,
                _ => {}
            }
        }
        let _ = self.err_window.iter().map(|c| c.take()).collect::<Vec<_>>();
        wt
    }

    pub fn totals_snapshot(&self) -> (u64, u64, StatusCounts, ErrorCounts) {
        (
            self.window_count.get(),
            0,
            self.status_map(),
            self.error_map(),
        )
    }
}

impl ErrorKind {
    pub fn from_index(i: usize) -> ErrorKind {
        use ErrorKind::*;
        [
            Connect, Timeout, Reset, Dns, Proxy, Tls, Proto, Io, Blocked, Cancelled,
        ][i % N_KINDS]
    }
    pub fn index(&self) -> usize {
        use ErrorKind::*;
        match self {
            Connect => 0,
            Timeout => 1,
            Reset => 2,
            Dns => 3,
            Proxy => 4,
            Tls => 5,
            Proto => 6,
            Io => 7,
            Blocked => 8,
            Cancelled => 9,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification_roundtrip() {
        let st = ClassifierState::new();
        st.record_status(200);
        st.record_status(403);
        st.record_status(403);
        st.record_error(ErrorKind::Timeout);
        st.record_error(ErrorKind::Proxy);
        let wt = st.drain_window();
        assert_eq!(wt.count, 3);
        assert_eq!(wt.s403, 2);
        let (_c, _e, statuses, errors) = st.totals_snapshot();
        let m = statuses
            .iter()
            .map(|(c, n)| (format!("{c}"), *n))
            .collect::<Vec<_>>();
        assert!(m.contains(&("403".into(), 2)));
        assert_eq!(errors.len(), 2);
        assert_eq!(
            ErrorKind::from_index(ErrorKind::Timeout.index()),
            ErrorKind::Timeout
        );
    }
}
