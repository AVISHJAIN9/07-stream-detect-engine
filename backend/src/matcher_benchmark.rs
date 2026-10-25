use std::time::Instant;

/// Benchmark Run Statistical Summary
#[derive(Debug, Clone, PartialEq)]
pub struct BenchmarkStats {
    pub name: String,
    pub iterations: usize,
    pub total_time_ms: f64,
    pub ops_per_sec: f64,
    pub throughput_mb_per_sec: f64,
    pub mean_ns: f64,
    pub std_dev_ns: f64,
    pub p50_ns: f64,
    pub p90_ns: f64,
    pub p99_ns: f64,
}

/// Pattern Matcher Micro-Benchmark Runner
pub struct BenchmarkRunner;

impl BenchmarkRunner {
    /// Executes a benchmark closure for N iterations and computes statistical metrics
    pub fn run_benchmark<F>(
        name: impl Into<String>,
        iterations: usize,
        bytes_per_iteration: usize,
        mut f: F,
    ) -> BenchmarkStats
    where
        F: FnMut(),
    {
        let mut sample_durations = Vec::with_capacity(iterations);

        // Warmup (10% of iterations, minimum 5)
        let warmup = (iterations / 10).max(5);
        for _ in 0..warmup {
            f();
        }

        let overall_start = Instant::now();
        for _ in 0..iterations {
            let iter_start = Instant::now();
            f();
            sample_durations.push(iter_start.elapsed().as_nanos() as f64);
        }
        let total_time_secs = overall_start.elapsed().as_secs_f64();

        sample_durations.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let sum: f64 = sample_durations.iter().sum();
        let mean = sum / (iterations as f64);

        let variance: f64 = sample_durations
            .iter()
            .map(|&val| (val - mean).powi(2))
            .sum::<f64>()
            / (iterations as f64);
        let std_dev = variance.sqrt();

        let p50_idx = ((iterations as f64) * 0.50) as usize;
        let p90_idx = ((iterations as f64) * 0.90).min((iterations - 1) as f64) as usize;
        let p99_idx = ((iterations as f64) * 0.99).min((iterations - 1) as f64) as usize;

        let p50 = sample_durations[p50_idx];
        let p90 = sample_durations[p90_idx];
        let p99 = sample_durations[p99_idx];

        let ops_per_sec = (iterations as f64) / total_time_secs;
        let total_bytes = (bytes_per_iteration * iterations) as f64;
        let throughput_mb = (total_bytes / (1024.0 * 1024.0)) / total_time_secs;

        BenchmarkStats {
            name: name.into(),
            iterations,
            total_time_ms: total_time_secs * 1000.0,
            ops_per_sec,
            throughput_mb_per_sec: throughput_mb,
            mean_ns: mean,
            std_dev_ns: std_dev,
            p50_ns: p50,
            p90_ns: p90,
            p99_ns: p99,
        }
    }
}
