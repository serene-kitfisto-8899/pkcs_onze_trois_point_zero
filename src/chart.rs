//! SVG chart rendering for benchmark results.
//!
//! Hand-rolled rather than pulled from a plotting crate: the output is three
//! fixed chart types over data we already hold, and SVG in a self-contained
//! file is more useful for a report than a PNG needing a rendering backend.

use crate::stats::{Phase, Samples, Summary, format_nanos};
use std::fmt::Write as _;

const WIDTH: f64 = 960.0;
const MARGIN_LEFT: f64 = 88.0;
const MARGIN_RIGHT: f64 = 28.0;
const PLOT_WIDTH: f64 = WIDTH - MARGIN_LEFT - MARGIN_RIGHT;

const HISTOGRAM_HEIGHT: f64 = 190.0;
const TIMELINE_HEIGHT: f64 = 170.0;
const BUCKETS: usize = 48;

const COLOURS: [&str; 4] = ["#7c8cf8", "#e8734a", "#4fb286", "#8a8f98"];

fn phase_colour(phase: Phase) -> &'static str {
    match phase {
        Phase::SignInit => COLOURS[0],
        Phase::Sign => COLOURS[1],
        Phase::Verify => COLOURS[2],
        Phase::Total => COLOURS[3],
    }
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Render the full report: one histogram and one timeline per phase, plus a
/// stacked bar showing where the time goes.
pub fn render(phases: &[(Phase, Samples)], title: &str) -> String {
    let panels: Vec<(Phase, &Samples, Summary)> = phases
        .iter()
        .filter_map(|(phase, samples)| samples.summary().map(|summary| (*phase, samples, summary)))
        .collect();

    if panels.is_empty() {
        return String::new();
    }

    let composition_height = 96.0;
    let panel_height = HISTOGRAM_HEIGHT + TIMELINE_HEIGHT + 108.0;
    let height = 96.0 + composition_height + panels.len() as f64 * panel_height + 24.0;

    let mut svg = String::with_capacity(64 * 1024);
    let _ = write!(
        svg,
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{height:.0}" viewBox="0 0 {WIDTH} {height:.0}" font-family="ui-sans-serif, system-ui, sans-serif">
<rect width="{WIDTH}" height="{height:.0}" fill="#ffffff"/>
<text x="{MARGIN_LEFT}" y="42" font-size="20" font-weight="600" fill="#1a1d23">{}</text>
<text x="{MARGIN_LEFT}" y="64" font-size="12" fill="#6b7280">Per-step signing latency &#183; sequential &#183; every sample retained</text>
"##,
        escape(title)
    );

    let mut y = 92.0;

    // Where the time actually goes. Uses total elapsed per phase, so it
    // reflects real cost share rather than a percentile artefact.
    if let Some(total) = panels.iter().find(|(p, _, _)| *p == Phase::Total) {
        let components: Vec<(Phase, f64)> = panels
            .iter()
            .filter(|(p, _, _)| *p != Phase::Total)
            .map(|(p, _, s)| (*p, s.total as f64))
            .collect();
        let sum: f64 = components.iter().map(|(_, v)| v).sum();
        if sum > 0.0 {
            svg.push_str(&composition_bar(&components, sum, total.2.total as f64, y));
        }
        y += composition_height;
    }

    for (phase, samples, summary) in &panels {
        svg.push_str(&panel(*phase, samples, summary, y));
        y += panel_height;
    }

    svg.push_str("</svg>\n");
    svg
}

/// Stacked bar: the share of total time each phase accounts for.
fn composition_bar(components: &[(Phase, f64)], sum: f64, total: f64, y: f64) -> String {
    let mut out = String::new();
    let _ = write!(
        out,
        r##"<text x="{MARGIN_LEFT}" y="{:.1}" font-size="13" font-weight="600" fill="#1a1d23">Where the time goes</text>"##,
        y + 12.0
    );

    let bar_y = y + 24.0;
    let bar_height = 26.0;
    let mut x = MARGIN_LEFT;

    for (phase, value) in components {
        let width = value / sum * PLOT_WIDTH;
        let share = value / sum * 100.0;
        let _ = write!(
            out,
            r##"<rect x="{x:.2}" y="{bar_y:.1}" width="{width:.2}" height="{bar_height}" fill="{}"/>"##,
            phase_colour(*phase)
        );
        // Only label segments wide enough to hold text legibly.
        if width > 62.0 {
            let _ = write!(
                out,
                r##"<text x="{:.2}" y="{:.1}" font-size="11" font-weight="600" fill="#ffffff" text-anchor="middle">{share:.1}%</text>"##,
                x + width / 2.0,
                bar_y + 17.0
            );
        }
        x += width;
    }

    // Legend, plus a note when the phases do not account for the whole total.
    // Segments are laid out on a fixed pitch rather than measured text width,
    // which cannot be computed without font metrics.
    let legend_y = bar_y + bar_height + 18.0;
    let pitch = PLOT_WIDTH / components.len().max(1) as f64;
    for (index, (phase, value)) in components.iter().enumerate() {
        let legend_x = MARGIN_LEFT + index as f64 * pitch;
        let _ = write!(
            out,
            r##"<rect x="{legend_x:.1}" y="{:.1}" width="10" height="10" rx="2" fill="{}"/><text x="{:.1}" y="{:.1}" font-size="11" fill="#4b5563">{} &#183; {} total</text>"##,
            legend_y - 9.0,
            phase_colour(*phase),
            legend_x + 15.0,
            legend_y,
            escape(phase.label()),
            escape(&format_nanos(*value))
        );
    }

    let unaccounted = total - sum;
    if unaccounted / total > 0.01 {
        let _ = write!(
            out,
            r##"<text x="{:.1}" y="{:.1}" font-size="11" fill="#9ca3af" text-anchor="end">{:.1}% unattributed (loop overhead)</text>"##,
            WIDTH - MARGIN_RIGHT,
            bar_y - 6.0,
            unaccounted / total * 100.0
        );
    }

    out
}

/// One phase: a latency distribution and a per-iteration timeline.
fn panel(phase: Phase, samples: &Samples, summary: &Summary, y: f64) -> String {
    let mut out = String::new();
    let colour = phase_colour(phase);

    let _ = write!(
        out,
        r##"<text x="{MARGIN_LEFT}" y="{:.1}" font-size="14" font-weight="600" fill="#1a1d23">{}</text>"##,
        y + 26.0,
        escape(phase.label())
    );
    let _ = write!(
        out,
        r##"<text x="{:.1}" y="{:.1}" font-size="11" fill="#6b7280" text-anchor="end">n={} &#183; p50 {} &#183; p99 {} &#183; max {}</text>"##,
        WIDTH - MARGIN_RIGHT,
        y + 26.0,
        summary.n,
        escape(&format_nanos(summary.p50 as f64)),
        escape(&format_nanos(summary.p99 as f64)),
        escape(&format_nanos(summary.max as f64)),
    );

    out.push_str(&histogram(samples, summary, colour, y + 40.0));
    out.push_str(&timeline(
        samples,
        summary,
        colour,
        y + 40.0 + HISTOGRAM_HEIGHT + 48.0,
    ));
    out
}

/// Latency distribution, with percentile markers overlaid.
fn histogram(samples: &Samples, summary: &Summary, colour: &str, y: f64) -> String {
    let mut out = String::new();
    let baseline = y + HISTOGRAM_HEIGHT;

    let min = summary.min as f64;
    // Clamp the x-axis at p999 so a lone outlier cannot squash the entire
    // distribution into the leftmost bucket. The excluded tail is annotated.
    let upper = (summary.p999 as f64).max(min + 1.0);
    let span = upper - min;

    let mut buckets = vec![0usize; BUCKETS];
    let mut beyond = 0usize;
    for value in samples.raw() {
        let v = *value as f64;
        if v > upper {
            beyond += 1;
            continue;
        }
        let index = (((v - min) / span) * (BUCKETS - 1) as f64).round() as usize;
        buckets[index.min(BUCKETS - 1)] += 1;
    }
    let peak = buckets.iter().copied().max().unwrap_or(1).max(1) as f64;

    let bucket_width = PLOT_WIDTH / BUCKETS as f64;
    for (i, count) in buckets.iter().enumerate() {
        if *count == 0 {
            continue;
        }
        let bar_height = (*count as f64 / peak) * (HISTOGRAM_HEIGHT - 12.0);
        let _ = write!(
            out,
            r##"<rect x="{:.2}" y="{:.2}" width="{:.2}" height="{:.2}" fill="{colour}" opacity="0.75"/>"##,
            MARGIN_LEFT + i as f64 * bucket_width,
            baseline - bar_height,
            (bucket_width - 1.0).max(0.6),
            bar_height
        );
    }

    let _ = write!(
        out,
        r##"<line x1="{MARGIN_LEFT}" y1="{baseline:.1}" x2="{:.1}" y2="{baseline:.1}" stroke="#d1d5db" stroke-width="1"/>"##,
        WIDTH - MARGIN_RIGHT
    );

    let position = |value: f64| MARGIN_LEFT + ((value - min) / span).clamp(0.0, 1.0) * PLOT_WIDTH;

    for (value, label, dash) in [
        (summary.p50 as f64, "p50", "none"),
        (summary.p99 as f64, "p99", "3 3"),
    ] {
        let x = position(value);
        let _ = write!(
            out,
            r##"<line x1="{x:.2}" y1="{:.1}" x2="{x:.2}" y2="{baseline:.1}" stroke="#1a1d23" stroke-width="1.2" stroke-dasharray="{dash}" opacity="0.65"/><text x="{:.2}" y="{:.1}" font-size="10" fill="#1a1d23">{label} {}</text>"##,
            y + 4.0,
            x + 4.0,
            y + 13.0,
            escape(&format_nanos(value))
        );
    }

    let _ = write!(
        out,
        r##"<text x="{MARGIN_LEFT}" y="{:.1}" font-size="10" fill="#6b7280">{}</text><text x="{:.1}" y="{:.1}" font-size="10" fill="#6b7280" text-anchor="end">{}</text>"##,
        baseline + 14.0,
        escape(&format_nanos(min)),
        WIDTH - MARGIN_RIGHT,
        baseline + 14.0,
        escape(&format_nanos(upper))
    );

    if beyond > 0 {
        let _ = write!(
            out,
            r##"<text x="{:.1}" y="{:.1}" font-size="10" fill="#9ca3af" text-anchor="end">{beyond} sample(s) beyond p999, up to {}</text>"##,
            WIDTH - MARGIN_RIGHT,
            baseline + 27.0,
            escape(&format_nanos(summary.max as f64))
        );
    }

    let _ = write!(
        out,
        r##"<text x="{:.1}" y="{:.1}" font-size="10" fill="#9ca3af" text-anchor="middle" transform="rotate(-90 {:.1} {:.1})">count</text>"##,
        MARGIN_LEFT - 30.0,
        y + HISTOGRAM_HEIGHT / 2.0,
        MARGIN_LEFT - 30.0,
        y + HISTOGRAM_HEIGHT / 2.0
    );

    out
}

/// Per-iteration timeline: exposes drift, periodic spikes, and warmup effects
/// that a distribution alone would hide.
fn timeline(samples: &Samples, summary: &Summary, colour: &str, y: f64) -> String {
    let mut out = String::new();
    let baseline = y + TIMELINE_HEIGHT;
    let values = samples.raw();
    if values.is_empty() {
        return out;
    }

    let min = summary.min as f64;
    let upper = (summary.max as f64).max(min + 1.0);
    let span = upper - min;
    let n = values.len();

    let _ = write!(
        out,
        r##"<rect x="{MARGIN_LEFT}" y="{y:.1}" width="{PLOT_WIDTH}" height="{TIMELINE_HEIGHT}" fill="#fafafa" stroke="#e5e7eb" stroke-width="1"/>"##
    );

    let p50_y = baseline - ((summary.p50 as f64 - min) / span) * TIMELINE_HEIGHT;
    let _ = write!(
        out,
        r##"<line x1="{MARGIN_LEFT}" y1="{p50_y:.2}" x2="{:.1}" y2="{p50_y:.2}" stroke="#1a1d23" stroke-width="1" opacity="0.45"/><text x="{:.1}" y="{:.2}" font-size="10" fill="#1a1d23" opacity="0.7">p50</text>"##,
        WIDTH - MARGIN_RIGHT,
        MARGIN_LEFT + 4.0,
        p50_y - 4.0
    );

    // Points for small runs; a min/max envelope once points would overplot.
    if n <= 1500 {
        let radius = if n > 600 { 1.0 } else { 1.6 };
        for (i, value) in values.iter().enumerate() {
            let x = MARGIN_LEFT + (i as f64 / (n.max(2) - 1) as f64) * PLOT_WIDTH;
            let py = baseline - ((*value as f64 - min) / span) * TIMELINE_HEIGHT;
            let _ = write!(
                out,
                r##"<circle cx="{x:.2}" cy="{py:.2}" r="{radius}" fill="{colour}" opacity="0.55"/>"##
            );
        }
    } else {
        let columns = 480usize;
        let per_column = n.div_ceil(columns);
        let mut lows = String::new();
        let mut highs: Vec<(f64, f64)> = Vec::new();
        for (column, chunk) in values.chunks(per_column).enumerate() {
            let low = *chunk.iter().min().unwrap() as f64;
            let high = *chunk.iter().max().unwrap() as f64;
            let x = MARGIN_LEFT + (column as f64 / (columns - 1) as f64) * PLOT_WIDTH;
            let _ = write!(
                lows,
                "{}{x:.2},{:.2}",
                if column == 0 { "" } else { " " },
                baseline - ((low - min) / span) * TIMELINE_HEIGHT
            );
            highs.push((x, baseline - ((high - min) / span) * TIMELINE_HEIGHT));
        }
        let mut path = lows;
        for (x, py) in highs.iter().rev() {
            let _ = write!(path, " {x:.2},{py:.2}");
        }
        let _ = write!(
            out,
            r##"<polygon points="{path}" fill="{colour}" opacity="0.5"/>"##
        );
    }

    let _ = write!(
        out,
        r##"<text x="{MARGIN_LEFT}" y="{:.1}" font-size="10" fill="#6b7280">iteration 0</text><text x="{:.1}" y="{:.1}" font-size="10" fill="#6b7280" text-anchor="end">{}</text>"##,
        baseline + 14.0,
        WIDTH - MARGIN_RIGHT,
        baseline + 14.0,
        n - 1
    );
    let _ = write!(
        out,
        r##"<text x="{:.1}" y="{:.1}" font-size="10" fill="#9ca3af" text-anchor="end">{}</text><text x="{:.1}" y="{:.1}" font-size="10" fill="#9ca3af" text-anchor="end">{}</text>"##,
        MARGIN_LEFT - 8.0,
        y + 10.0,
        escape(&format_nanos(upper)),
        MARGIN_LEFT - 8.0,
        baseline,
        escape(&format_nanos(min))
    );

    out
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

    fn phases() -> Vec<(Phase, Samples)> {
        vec![
            (Phase::SignInit, samples_of(&[10, 12, 11, 13, 40])),
            (Phase::Sign, samples_of(&[100, 110, 105, 120, 400])),
            (Phase::Verify, samples_of(&[50, 52, 51, 53, 60])),
            (Phase::Total, samples_of(&[160, 174, 167, 186, 500])),
        ]
    }

    #[test]
    fn renders_well_formed_svg() {
        let svg = render(&phases(), "test run");
        assert!(svg.starts_with("<svg"));
        assert!(svg.trim_end().ends_with("</svg>"));
        assert_eq!(svg.matches("<svg").count(), 1);
    }

    #[test]
    fn includes_every_phase_label() {
        let svg = render(&phases(), "test run");
        for phase in Phase::ALL {
            assert!(svg.contains(phase.label()), "missing {}", phase.label());
        }
    }

    #[test]
    fn empty_input_renders_nothing() {
        assert!(render(&[], "empty").is_empty());
        let empty = vec![(Phase::Sign, Samples::with_capacity(0))];
        assert!(render(&empty, "empty").is_empty());
    }

    #[test]
    fn escapes_title_markup() {
        let svg = render(&phases(), "a <b> & c");
        assert!(svg.contains("a &lt;b&gt; &amp; c"));
        assert!(!svg.contains("<b>"));
    }

    #[test]
    fn handles_identical_samples_without_dividing_by_zero() {
        let flat = vec![(Phase::Sign, samples_of(&[500; 40]))];
        let svg = render(&flat, "flat");
        assert!(svg.contains("</svg>"));
        assert!(!svg.contains("NaN"));
        assert!(!svg.contains("inf"));
    }

    #[test]
    fn handles_single_sample() {
        let one = vec![(Phase::Sign, samples_of(&[42]))];
        let svg = render(&one, "one");
        assert!(svg.contains("</svg>"));
        assert!(!svg.contains("NaN"));
    }

    #[test]
    fn large_runs_switch_to_envelope_rendering() {
        let values: Vec<u64> = (0..4000).map(|i| 1000 + (i % 97)).collect();
        let big = vec![(Phase::Sign, samples_of(&values))];
        let svg = render(&big, "big");
        assert!(svg.contains("<polygon"));
        assert!(!svg.contains("NaN"));
    }

    #[test]
    fn small_runs_plot_individual_points() {
        let svg = render(&phases(), "small");
        assert!(svg.contains("<circle"));
    }
}
