//! Latency sample collection and reporting.
//!
//! Every sample is retained as nanoseconds so percentiles can be computed
//! exactly. Percentiles matter more than the mean here: the dominant term is
//! a network round trip, where a single retransmit drags the mean while p50
//! still describes the typical case.

use serde::Serialize;
use std::time::Instant;

use crate::pkcs11::Curve;

/// The phases timed per iteration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    SignInit,
    Sign,
    Verify,
    Total,
}

impl Phase {
    pub fn label(&self) -> &'static str {
        match self {
            Phase::SignInit => "C_SignInit",
            Phase::Sign => "C_Sign (network)",
            Phase::Verify => "verify (local)",
            Phase::Total => "total",
        }
    }

    pub fn label_for_curve(&self, curve: Curve) -> &'static str {
        match (self, curve) {
            (Phase::SignInit, Curve::Ed25519) => "C_MessageSignInit (setup)",
            (Phase::Sign, Curve::Ed25519) => "C_SignMessage (network)",
            _ => self.label(),
        }
    }

    pub fn key(&self) -> &'static str {
        match self {
            Phase::SignInit => "sign_init",
            Phase::Sign => "sign",
            Phase::Verify => "verify",
            Phase::Total => "total",
        }
    }

    pub const ALL: [Phase; 4] = [Phase::SignInit, Phase::Sign, Phase::Verify, Phase::Total];
}

/// Nanosecond samples for one phase, preallocated so the timed loop never
/// grows a vector.
#[derive(Debug, Clone)]
pub struct Samples {
    values: Vec<u64>,
}

impl Samples {
    pub fn with_capacity(n: usize) -> Self {
        Self {
            values: Vec::with_capacity(n),
        }
    }

    #[inline]
    pub fn push(&mut self, nanos: u64) {
        self.values.push(nanos);
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn raw(&self) -> &[u64] {
        &self.values
    }

    pub fn summary(&self) -> Option<Summary> {
        if self.values.is_empty() {
            return None;
        }
        let mut sorted = self.values.clone();
        sorted.sort_unstable();

        let n = sorted.len();
        let sum: u128 = sorted.iter().map(|v| *v as u128).sum();
        let mean = sum as f64 / n as f64;
        let variance = sorted
            .iter()
            .map(|v| {
                let d = *v as f64 - mean;
                d * d
            })
            .sum::<f64>()
            / n as f64;

        Some(Summary {
            n,
            min: sorted[0],
            p50: percentile(&sorted, 0.50),
            p90: percentile(&sorted, 0.90),
            p99: percentile(&sorted, 0.99),
            p999: percentile(&sorted, 0.999),
            max: sorted[n - 1],
            mean,
            stddev: variance.sqrt(),
            total: sum,
        })
    }
}

/// Nearest-rank percentile. With every sample retained this is exact, so no
/// interpolation is needed.
fn percentile(sorted: &[u64], q: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = (q * sorted.len() as f64).ceil() as usize;
    let index = rank.saturating_sub(1).min(sorted.len() - 1);
    sorted[index]
}

#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    pub n: usize,
    pub min: u64,
    pub p50: u64,
    pub p90: u64,
    pub p99: u64,
    pub p999: u64,
    pub max: u64,
    pub mean: f64,
    pub stddev: f64,
    #[serde(skip)]
    pub total: u128,
}

impl Summary {
    /// Signatures per second implied by this phase's p50.
    pub fn throughput_p50(&self) -> f64 {
        if self.p50 == 0 {
            return f64::INFINITY;
        }
        1e9 / self.p50 as f64
    }

    /// Signatures per second over the whole measured run.
    pub fn throughput_mean(&self) -> f64 {
        if self.mean <= 0.0 {
            return f64::INFINITY;
        }
        1e9 / self.mean
    }
}

/// Format nanoseconds with a unit that keeps roughly four significant digits.
pub fn format_nanos(nanos: f64) -> String {
    if nanos < 1_000.0 {
        format!("{nanos:.0} ns")
    } else if nanos < 1_000_000.0 {
        format!("{:.2} µs", nanos / 1_000.0)
    } else if nanos < 1_000_000_000.0 {
        format!("{:.3} ms", nanos / 1_000_000.0)
    } else {
        format!("{:.3} s", nanos / 1_000_000_000.0)
    }
}

/// Measure the cost of the clock itself, to document the noise floor.
///
/// The result is reported in the run header so a reader can tell how much of
/// a small phase measurement is the measurement apparatus.
pub fn measure_clock_overhead(iterations: usize) -> f64 {
    let mut total = 0u64;
    for _ in 0..iterations {
        let start = Instant::now();
        let inner = Instant::now();
        total += start.elapsed().as_nanos() as u64;
        std::hint::black_box(inner);
    }
    total as f64 / iterations as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn samples_of(values: &[u64]) -> Samples {
        let mut s = Samples::with_capacity(values.len());
        for v in values {
            s.push(*v);
        }
        s
    }

    #[test]
    fn empty_samples_have_no_summary() {
        assert!(Samples::with_capacity(4).summary().is_none());
    }

    #[test]
    fn summary_computes_exact_percentiles() {
        let values: Vec<u64> = (1..=100).collect();
        let summary = samples_of(&values).summary().unwrap();
        assert_eq!(summary.n, 100);
        assert_eq!(summary.min, 1);
        assert_eq!(summary.max, 100);
        assert_eq!(summary.p50, 50);
        assert_eq!(summary.p90, 90);
        assert_eq!(summary.p99, 99);
        assert_eq!(summary.mean, 50.5);
    }

    #[test]
    fn percentiles_are_order_independent() {
        let ascending = samples_of(&[1, 2, 3, 4, 5]).summary().unwrap();
        let shuffled = samples_of(&[4, 1, 5, 3, 2]).summary().unwrap();
        assert_eq!(ascending.p50, shuffled.p50);
        assert_eq!(ascending.max, shuffled.max);
    }

    #[test]
    fn outlier_moves_mean_but_not_median() {
        let clean = samples_of(&[10; 99]);
        let mut noisy = clean.clone();
        noisy.push(100_000);
        let a = clean.summary().unwrap();
        let b = noisy.summary().unwrap();
        assert_eq!(a.p50, b.p50);
        assert!(b.mean > a.mean * 10.0);
    }

    #[test]
    fn single_sample_summary() {
        let summary = samples_of(&[42]).summary().unwrap();
        assert_eq!(summary.min, 42);
        assert_eq!(summary.p999, 42);
        assert_eq!(summary.stddev, 0.0);
    }

    #[test]
    fn throughput_derives_from_p50() {
        let summary = samples_of(&[1_000_000]).summary().unwrap();
        assert!((summary.throughput_p50() - 1000.0).abs() < 1e-6);
    }

    #[test]
    fn formats_units_by_magnitude() {
        assert_eq!(format_nanos(500.0), "500 ns");
        assert_eq!(format_nanos(1_500.0), "1.50 µs");
        assert_eq!(format_nanos(2_500_000.0), "2.500 ms");
        assert_eq!(format_nanos(3_000_000_000.0), "3.000 s");
    }
}
