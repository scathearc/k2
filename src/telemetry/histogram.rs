//! Lock-free High-Dynamic-Range latency histograms.
//!
//! Logarithmic bucketing with `1 << SUB_BITS` sub-buckets per exponent gives
//! ~1/SUB_BITS relative resolution with O(1) recording, fixed allocation, and
//! atomically incremented counters (no locks on the recording hot path).

use std::sync::atomic::{AtomicU64, Ordering};

const SUB_BITS: u32 = 7;
const SUB: u64 = 1 << SUB_BITS;
pub const MAX_VALUE_NS: u64 = 10_000_000_000_000; // ~2.7h ceiling

/// Shared dimensions describing index math over a fixed value range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HdrConfig {
    pub min: u64,
    pub max: u64,
}

impl HdrConfig {
    pub fn new(min: u64, max: u64) -> Self {
        assert!(min > 0 && max > min);
        Self { min, max }
    }
    pub fn n_buckets(&self) -> usize {
        Self::index_for(self.max, self.max) + 1
    }
    pub(crate) fn index_for(_min: u64, v: u64) -> usize {
        // for min low values below 2^p this is the linear region
        let e = (usize::BITS - 1 - v.max(1).leading_zeros()) as usize;
        if (e as u32) < SUB_BITS {
            v as usize
        } else {
            let sub_bits_flat = 1usize << SUB_BITS;
            sub_bits_flat
                + ((e - SUB_BITS as usize) << SUB_BITS)
                + (((v as usize) >> (e - SUB_BITS as usize)) - sub_bits_flat)
        }
    }
}

/// Empty-bucket index math helper shared with histograms built on identical config.
pub fn index_of(cfg: &HdrConfig, v: u64) -> usize {
    HdrConfig::index_for(cfg.min, v)
}

pub struct AtomicHdr {
    cfg: HdrConfig,
    counts: Box<[AtomicU64]>,
}

impl std::fmt::Debug for AtomicHdr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AtomicHdr").field("cfg", &self.cfg).finish()
    }
}

impl AtomicHdr {
    pub fn new(min: u64, max: u64) -> Self {
        let cfg = HdrConfig::new(min, max);
        let counts = (0..cfg.n_buckets())
            .map(|_| AtomicU64::new(0))
            .collect::<Box<[_]>>();
        Self { cfg, counts }
    }
    pub fn cfg(&self) -> HdrConfig {
        self.cfg
    }
    #[inline]
    pub fn record(&self, v: u64) {
        let v = v.clamp(self.cfg.min, self.cfg.max);
        let idx = HdrConfig::index_for(self.cfg.min, v);
        // Safety: index_for is monotone & bounded by construction (asserted in tests)
        self.counts[idx].fetch_add(1, Ordering::Relaxed);
    }

    /// Atomically take-and-clear: returns the drained bucket counts.
    pub fn drain(&self) -> Vec<u64> {
        self.counts
            .iter()
            .map(|c| c.swap(0, Ordering::Relaxed))
            .collect()
    }

    /// Read-only snapshot without clearing (cumulative use).
    pub fn load(&self) -> Vec<u64> {
        self.counts
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .collect()
    }
}

/// Plain, merged histogram good for quantile/mean queries.
#[derive(Debug, Clone)]
pub struct Agg {
    pub cfg: HdrConfig,
    pub counts: Vec<u64>,
    pub total: u64,
}

impl Agg {
    pub fn empty(cfg: HdrConfig) -> Self {
        Self {
            cfg,
            counts: vec![0; cfg.n_buckets()],
            total: 0,
        }
    }
    pub fn add_bucket(&mut self, counts: &[u64]) {
        debug_assert_eq!(self.counts.len(), counts.len());
        for (i, c) in counts.iter().enumerate() {
            self.counts[i] += c;
        }
        self.recount();
    }
    pub fn recount(&mut self) {
        self.total = self.counts.iter().sum();
    }

    /// Highest bucket bound covering the q-quantile (conservative, HDR-style).
    pub fn quantile(&self, q: f64) -> Option<u64> {
        if self.total == 0 {
            return None;
        }
        let target = ((self.total as f64) * q.clamp(0.0, 1.0)).ceil() as u64;
        let target = target.clamp(1, self.total);
        let mut cum = 0u64;
        for (b, c) in self.counts.iter().enumerate() {
            if *c == 0 {
                continue;
            }
            cum += c;
            if cum >= target {
                return Some(Self::bucket_high(&self.cfg, b));
            }
        }
        None
    }

    pub fn mean(&self) -> Option<f64> {
        if self.total == 0 {
            return None;
        }
        let mut sum = 0u128;
        for (b, c) in self.counts.iter().enumerate() {
            if *c == 0 {
                continue;
            }
            let (lo, hi) = Self::bucket_bounds(&self.cfg, b);
            let mid = lo + ((hi - lo + 1) >> 1);
            sum += (mid as u128) * (*c as u128);
        }
        Some(sum as f64 / self.total as f64)
    }

    pub fn bucket_bounds(_cfg: &HdrConfig, b: usize) -> (u64, u64) {
        let sub_bits = SUB as usize;
        if b < sub_bits {
            return (b as u64, b as u64);
        }
        let rel = b - sub_bits;
        let e = (rel >> SUB_BITS) + SUB_BITS as usize;
        let sub = rel & (sub_bits - 1);
        let base = 1u64 << e;
        let width = 1u64 << (e - SUB_BITS as usize);
        let lo = base + (sub as u64) * width;
        let hi = base + ((sub + 1) as u64) * width - 1;
        (lo, hi)
    }

    fn bucket_high(cfg: &HdrConfig, b: usize) -> u64 {
        Self::bucket_bounds(cfg, b).1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indexing_is_monotone_and_bounded() {
        let cfg = HdrConfig::new(1, MAX_VALUE_NS);
        let nb = cfg.n_buckets();
        let mut prev = 0usize;
        for shift in 0..40 {
            let v = (1u64 << shift) + (1u64 << (shift / 2));
            let idx = HdrConfig::index_for(1, v);
            assert!(idx >= prev, "index regression at {shift}");
            assert!(idx < nb, "index {idx} overflow buckets {nb}");
            prev = idx;
        }
    }

    #[test]
    fn bucket_bounds_align_with_index() {
        let cfg = HdrConfig::new(1, MAX_VALUE_NS);
        for b in [
            0usize,
            5,
            128,
            129,
            255,
            256,
            700,
            2000,
            cfg.n_buckets() - 1,
        ] {
            let (lo, hi) = Agg::bucket_bounds(&cfg, b);
            assert!(lo <= hi, "bucket {b}: lo {lo} > hi {hi}");
            if lo == 0 {
                continue; // bucket 0 covers the zero clamp region
            }
            assert_eq!(
                HdrConfig::index_for(1, lo),
                b,
                "bucket {b} lower bound {lo} must map back to itself"
            );
        }
    }

    #[test]
    fn quantiles_reflect_recorded_samples() {
        let h = AtomicHdr::new(1, MAX_VALUE_NS);
        for i in 1..=1000u64 {
            h.record(i * 1_000); // 1us .. 1ms
        }
        let agg = Agg {
            cfg: h.cfg(),
            counts: h.load(),
            total: 1000,
        };
        let p50 = agg.quantile(0.5).unwrap();
        let p99 = agg.quantile(0.99).unwrap();
        assert!((490_000..=520_000).contains(&p50), "p50 {p50}");
        assert!((980_000..=1_010_000).contains(&p99), "p99 {p99}");
        let mean = agg.mean().unwrap();
        assert!((490_000.0..=510_000.0).contains(&mean), "mean {mean}");
    }

    #[test]
    fn drain_clears_and_returns_counts() {
        let h = AtomicHdr::new(1, MAX_VALUE_NS);
        for i in 1..=10u64 {
            h.record(i);
        }
        assert_eq!(h.drain().iter().sum::<u64>(), 10);
        assert_eq!(h.load().iter().sum::<u64>(), 0);
    }
}
