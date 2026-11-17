import json

import pytest

from eval import main


def test_eval_cli_reports_detection_metrics_and_benchmark(tmp_path, capsys):
    samples = {
        "positive": ['api_key = "DemoSecret9876"'],
        "negative": [
            "UUID=550e8400-e29b-41d4-a716-446655440000",
            "sha256=0123456789abcdef",
            "sk_test_0123456789abcdef",
        ],
        "evasion": ['api_key = "abc" + "defghijkl"'],
    }
    paths = {}
    for label, entries in samples.items():
        path = tmp_path / f"{label}.json"
        path.write_text(json.dumps(entries), encoding="utf-8")
        paths[label] = str(path)

    assert main(
        [
            "--positive",
            paths["positive"],
            "--negative",
            paths["negative"],
            "--evasion",
            paths["evasion"],
            "--iterations",
            "2",
        ]
    ) == 0

    report = json.loads(capsys.readouterr().out)
    assert report["sample_counts"] == {"positive": 1, "negative": 3, "evasion": 1}
    for metrics in report["results"].values():
        assert metrics["positive_recall"] == 1.0
        assert metrics["evasion_recall"] == 0.0
        assert metrics["overall_recall"] == 0.5
        assert metrics["false_alarm_rate"] == pytest.approx(1 / 3)
        assert metrics["latency_p95_ms"] >= metrics["latency_p50_ms"] >= 0
        assert metrics["throughput_samples_per_second"] > 0
