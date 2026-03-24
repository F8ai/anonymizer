"""Benchmark helpers (latency over token-sized windows)."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from anonymizer.bench import (
    DEFAULT_WINDOWS,
    _format_table,
    build_corpus,
    run_latency,
)


def test_build_corpus_non_empty() -> None:
    text, label = build_corpus(64, seed=1)
    assert len(text) >= 1
    assert label >= 1


def test_run_latency_small_window() -> None:
    rows = run_latency(windows=[32], repeats=2, warmup=1, cfg={})
    assert len(rows) == 1
    r = rows[0]
    assert r["target_tokens"] == 32
    assert r["chars"] >= 1
    assert r["ms_mean"] >= 0


def test_format_table() -> None:
    s = _format_table(
        [
            {
                "target_tokens": 100,
                "label_tokens": 100,
                "chars": 400,
                "ms_mean": 1.5,
                "ms_stdev": 0.1,
                "ms_min": 1.4,
                "ms_max": 1.6,
                "repeats": 3,
            }
        ]
    )
    assert "100" in s
    assert "1.5" in s


def test_default_windows_sensible() -> None:
    assert 512 in DEFAULT_WINDOWS
    assert DEFAULT_WINDOWS == tuple(sorted(DEFAULT_WINDOWS))
    assert DEFAULT_WINDOWS[0] >= 256


def test_bench_cli_smoke(repo_root: Path) -> None:
    env = {**os.environ, "PYTHONPATH": str(repo_root / "src")}
    r = subprocess.run(
        [
            sys.executable,
            "-m",
            "anonymizer.bench",
            "--windows",
            "24,48",
            "--repeats",
            "1",
            "--warmup",
            "0",
        ],
        capture_output=True,
        text=True,
        cwd=repo_root,
        env=env,
    )
    assert r.returncode == 0, r.stderr
    assert "latency" in r.stdout.lower() or "tokens" in r.stdout.lower()
