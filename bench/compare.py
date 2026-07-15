#!/usr/bin/env python3
# compare.py — merge engine + kernel bench CSVs into a single markdown table.
#
# Reads CSVs produced by run_engine_bench.sh and run_kernel_bench.sh and
# emits a markdown table comparing the three backends.  The schema is
# stable: each CSV has the header
#
#   timestamp,backend,pps,drops,p50_us,p99_us
#
# Comparison strategy for repeated live runs:
#   - For each backend, group files by <backend>_trial*.csv.
#   - Compute per-trial aggregates: median pps, mean drops/s, median
#     p50_us, median p99_us.
#   - Take the median over trials for the final table cell.
#   - Latency cells are reported as N/A when the underlying CSV records
#     N/A (e.g. kernel_nftables has no p50/p99 from /proc counters).
#
# Output:
#   bench/results/comparison.md  (default; --out to override)
#
# Usage:
#   python3 bench/compare.py
#   python3 bench/compare.py --results-dir bench/results --out bench/results/comparison.md
#   python3 bench/compare.py --csv bench/results/engine_af_xdp_trial1.csv ...

from __future__ import annotations

import argparse
import csv
import glob
import os
import re
import statistics
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# Backends the plan explicitly calls out.  We render a row for each, even
# when the corresponding CSV is missing — the cell is left as N/A.
EXPECTED_BACKENDS = ["engine_af_xdp", "engine_dpdk", "kernel_nftables"]

TRIAL_RE = re.compile(r"^(?P<backend>.+)_trial(?P<n>\d+)\.csv$")


@dataclass
class TrialAggregate:
    pps_median: float = float("nan")
    drops_per_sec_mean: float = float("nan")
    p50_us_median: float = float("nan")
    p99_us_median: float = float("nan")
    samples: int = 0
    drops_total: int = 0


@dataclass
class BackendSummary:
    backend: str
    trials: List[TrialAggregate] = field(default_factory=list)
    available: bool = False


def _to_float(s: str) -> Optional[float]:
    if s in (None, "", "N/A", "n/a", "NaN", "nan"):
        return None
    try:
        return float(s)
    except ValueError:
        return None


def _aggregate_csv(path: str) -> Optional[TrialAggregate]:
    """Return a TrialAggregate for a single CSV, or None on read failure."""
    if not os.path.isfile(path):
        return None
    pps_vals: List[float] = []
    drops_vals: List[float] = []
    p50_vals: List[float] = []
    p99_vals: List[float] = []
    drops_total = 0
    samples = 0
    with open(path, newline="") as fp:
        reader = csv.DictReader(fp)
        if reader.fieldnames is None or "pps" not in reader.fieldnames:
            return None
        for row in reader:
            samples += 1
            pps = _to_float(row.get("pps", ""))
            drops = _to_float(row.get("drops", ""))
            p50 = _to_float(row.get("p50_us", ""))
            p99 = _to_float(row.get("p99_us", ""))
            if pps is not None:
                pps_vals.append(pps)
            if drops is not None:
                drops_vals.append(drops)
                drops_total += int(drops)
            if p50 is not None:
                p50_vals.append(p50)
            if p99 is not None:
                p99_vals.append(p99)
    if samples == 0:
        return None
    return TrialAggregate(
        pps_median=statistics.median(pps_vals) if pps_vals else float("nan"),
        drops_per_sec_mean=(sum(drops_vals) / len(drops_vals)) if drops_vals else float("nan"),
        p50_us_median=statistics.median(p50_vals) if p50_vals else float("nan"),
        p99_us_median=statistics.median(p99_vals) if p99_vals else float("nan"),
        samples=samples,
        drops_total=drops_total,
    )


def _median(xs: List[float]) -> float:
    xs = [x for x in xs if not _is_nan(x)]
    if not xs:
        return float("nan")
    return statistics.median(xs)


def _is_nan(x: float) -> bool:
    return x != x  # NaN != NaN


def _fmt(value: float, kind: str) -> str:
    if _is_nan(value):
        return "N/A"
    if kind == "pps":
        return f"{int(round(value)):,}"
    if kind == "drops":
        return f"{value:.1f}"
    if kind == "us":
        return f"{value:.1f}"
    return f"{value}"


def discover(results_dir: str) -> Dict[str, BackendSummary]:
    out: Dict[str, BackendSummary] = {b: BackendSummary(backend=b) for b in EXPECTED_BACKENDS}
    # Allow user-supplied CSVs on the CLI to extend the discovery set.
    for path in sorted(glob.glob(os.path.join(results_dir, "*_trial*.csv"))):
        m = TRIAL_RE.match(os.path.basename(path))
        if not m:
            continue
        backend = m.group("backend")
        agg = _aggregate_csv(path)
        if agg is None:
            continue
        if backend not in out:
            out[backend] = BackendSummary(backend=backend)
        out[backend].trials.append(agg)
        out[backend].available = True
    return out


def discover_extra(paths: List[str]) -> Dict[str, BackendSummary]:
    """For each --csv argument, treat the filename the same way."""
    out: Dict[str, BackendSummary] = {}
    for path in paths:
        m = TRIAL_RE.match(os.path.basename(path))
        if not m:
            continue
        backend = m.group("backend")
        agg = _aggregate_csv(path)
        if agg is None:
            continue
        out.setdefault(backend, BackendSummary(backend=backend)).trials.append(agg)
        out[backend].available = True
    return out


def build_table(summaries: Dict[str, BackendSummary]) -> str:
    """Render the markdown table.  Backends preserve EXPECTED_BACKENDS order;
    extra backends (e.g. kernel_iptables) are appended in the order they were
    discovered."""
    ordered: List[str] = list(EXPECTED_BACKENDS)
    for b in summaries:
        if b not in ordered:
            ordered.append(b)

    lines: List[str] = []
    lines.append("# Packet Engine Benchmark Comparison")
    lines.append("")
    lines.append("Each cell is the **median over available trials**; collect at least five measured trials.")
    lines.append("A cell reads `N/A` if no CSV was found, or the underlying metric is N/A in the source.")
    lines.append("")
    lines.append("| Backend | pps | drops/s | p50_us | p99_us | trials | samples/trial |")
    lines.append("|---------|-----|---------|--------|--------|--------|---------------|")

    for backend in ordered:
        summary = summaries.get(backend)
        if summary is None or not summary.trials:
            lines.append(f"| {backend} | N/A | N/A | N/A | N/A | 0 | N/A |")
            continue
        n_trials = len(summary.trials)
        samples_per_trial = summary.trials[0].samples
        pps_med = _median([t.pps_median for t in summary.trials])
        drops_mean = _median([t.drops_per_sec_mean for t in summary.trials])
        p50_med = _median([t.p50_us_median for t in summary.trials])
        p99_med = _median([t.p99_us_median for t in summary.trials])
        lines.append(
            "| {backend} | {pps} | {drops} | {p50} | {p99} | {n} | {s} |".format(
                backend=backend,
                pps=_fmt(pps_med, "pps"),
                drops=_fmt(drops_mean, "drops"),
                p50=_fmt(p50_med, "us"),
                p99=_fmt(p99_med, "us"),
                n=n_trials,
                s=samples_per_trial,
            )
        )
    lines.append("")
    return "\n".join(lines)


def build_methodology(summaries: Dict[str, BackendSummary]) -> str:
    out: List[str] = []
    out.append("## Methodology")
    out.append("")
    out.append("Workload: 60 s of `tcpreplay --intf1=veth1 --mbps=1000` of a 10 s capture from the same harness.")
    out.append("Sampling: 1 Hz of the engine's `/metrics` endpoint (counter deltas + histogram bounds), or nftables")
    out.append("counter deltas for the kernel stack.")
    out.append("")
    out.append("### Per-trial aggregates")
    out.append("")
    out.append("| Backend | Trial | pps (median) | drops/s (mean) | p50_us (median) | p99_us (median) | samples |")
    out.append("|---------|-------|--------------|----------------|------------------|------------------|---------|")
    for backend in EXPECTED_BACKENDS:
        summary = summaries.get(backend)
        if summary is None or not summary.trials:
            out.append(f"| {backend} | - | N/A | N/A | N/A | N/A | N/A |")
            continue
        for i, t in enumerate(summary.trials, start=1):
            out.append(
                "| {b} | {i} | {pps} | {dr} | {p50} | {p99} | {s} |".format(
                    b=backend,
                    i=i,
                    pps=_fmt(t.pps_median, "pps"),
                    dr=_fmt(t.drops_per_sec_mean, "drops"),
                    p50=_fmt(t.p50_us_median, "us"),
                    p99=_fmt(t.p99_us_median, "us"),
                    s=t.samples,
                )
            )
    out.append("")
    return "\n".join(out)


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--results-dir", default="bench/results",
                   help="directory containing <backend>_trial<N>.csv (default: bench/results)")
    p.add_argument("--out", default="bench/results/comparison.md",
                   help="output markdown path (default: bench/results/comparison.md)")
    p.add_argument("--csv", action="append", default=[],
                   help="explicit CSV file(s) to include (can be repeated)")
    args = p.parse_args(argv)

    summaries = discover(args.results_dir)
    extra = discover_extra(args.csv)
    for backend, summary in extra.items():
        if backend not in summaries:
            summaries[backend] = summary
        else:
            summaries[backend].trials.extend(summary.trials)
            summaries[backend].available = True

    md = build_table(summaries) + "\n" + build_methodology(summaries)

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w") as fp:
        fp.write(md)
    print(f"[compare] wrote {args.out}")
    print("---- comparison.md ----")
    print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
