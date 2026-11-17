"""Benchmark secret detection against a simple regex baseline.

Samples are newline-delimited text by default. JSON files may contain a list
of strings for samples that span multiple lines.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path
from typing import Callable, Sequence

from security_proxy import scan_and_sanitize


_BASELINE_PATTERNS = (
    re.compile(
        r"\b(?:sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}|"
        r"(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})|"
        r"(?:AKIA|ASIA)[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|"
        r"xox[abposr]-[A-Za-z0-9-]{10,}|"
        r"(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,})"
    ),
    re.compile(
        r"(?i)\b[\w.-]*(?:api[_-]?key|secret|passwd|password|pwd|token|auth)"
        r"[\w.-]*[ \t]*[:=][ \t]*['\"]?[^'\"\s,;]{4,}"
    ),
    re.compile(
        r"\b(?:postgres(?:ql)?|mongodb(?:\+srv)?|mysql(?:\+pymysql)?|mariadb)"
        r"://[^\s\"'<>]+"
    ),
    re.compile(
        r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----.*?"
        r"-----END (?:[A-Z]+ )?PRIVATE KEY-----",
        re.DOTALL,
    ),
)


def _read_samples(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8-sig")
    if path.suffix.lower() == ".json":
        samples = json.loads(text)
        if not isinstance(samples, list) or not all(
            isinstance(sample, str) for sample in samples
        ):
            raise ValueError(f"{path}: expected a JSON array of strings")
        return samples
    if path.suffix.lower() == ".jsonl":
        samples = []
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            sample = json.loads(line)
            if not isinstance(sample, str):
                raise ValueError(f"{path}:{line_number}: expected a JSON string")
            samples.append(sample)
        return samples
    return [line for line in text.splitlines() if line.strip()]


def _percentile(values: Sequence[float], percentile: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * percentile
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def _evaluate(
    detector: Callable[[str], bool],
    positive: Sequence[str],
    negative: Sequence[str],
    evasion: Sequence[str],
    iterations: int,
) -> dict[str, float]:
    groups = (positive, negative, evasion)
    samples = [sample for group in groups for sample in group]

    for sample in samples:
        detector(sample)

    latencies: list[float] = []
    started = time.perf_counter()
    for _ in range(iterations):
        for sample in samples:
            sample_started = time.perf_counter()
            detector(sample)
            latencies.append(time.perf_counter() - sample_started)
    elapsed = time.perf_counter() - started

    def detection_rate(group: Sequence[str], expected_detection: bool) -> float:
        if not group:
            return 0.0
        detected = sum(detector(sample) for sample in group)
        correct = detected if expected_detection else len(group) - detected
        return correct / len(group)

    positive_recall = detection_rate(positive, True)
    evasion_recall = detection_rate(evasion, True)
    positive_total = len(positive) + len(evasion)
    overall_recall = (
        (positive_recall * len(positive) + evasion_recall * len(evasion))
        / positive_total
        if positive_total
        else 0.0
    )
    return {
        "positive_recall": positive_recall,
        "evasion_recall": evasion_recall,
        "overall_recall": overall_recall,
        "false_alarm_rate": 1.0 - detection_rate(negative, False),
        "latency_p50_ms": _percentile(latencies, 0.50) * 1000,
        "latency_p95_ms": _percentile(latencies, 0.95) * 1000,
        "throughput_samples_per_second": len(samples) * iterations / elapsed,
    }


def _project_detector(sample: str) -> bool:
    _, detections = scan_and_sanitize(sample)
    return bool(detections)


def _baseline_detector(sample: str) -> bool:
    return any(pattern.search(sample) for pattern in _BASELINE_PATTERNS)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--positive", required=True, type=Path, help="known secret samples")
    parser.add_argument("--negative", required=True, type=Path, help="benign samples")
    parser.add_argument("--evasion", required=True, type=Path, help="obfuscated secret samples")
    parser.add_argument(
        "--iterations",
        type=int,
        default=100,
        help="benchmark passes over the combined samples (default: 100)",
    )
    args = parser.parse_args(argv)
    if args.iterations < 1:
        parser.error("--iterations must be at least 1")

    try:
        positive = _read_samples(args.positive)
        negative = _read_samples(args.negative)
        evasion = _read_samples(args.evasion)
        for label, samples in (
            ("positive", positive),
            ("negative", negative),
            ("evasion", evasion),
        ):
            if not samples:
                raise ValueError(f"{label} samples must not be empty")
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        parser.error(str(exc))

    results = {
        "project_detector": _evaluate(
            _project_detector, positive, negative, evasion, args.iterations
        ),
        "basic_regex_baseline": _evaluate(
            _baseline_detector, positive, negative, evasion, args.iterations
        ),
    }
    report = {
        "iterations": args.iterations,
        "sample_counts": {
            "positive": len(positive),
            "negative": len(negative),
            "evasion": len(evasion),
        },
        "rate_scale": "0.0-1.0",
        "results": results,
    }
    json.dump(report, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
