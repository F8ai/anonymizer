from __future__ import annotations

import io
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def test_cli_main_inprocess(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr("sys.argv", ["anonymize-prompt"])
    monkeypatch.setattr("sys.stdin", io.StringIO("x@y.co"))
    from anonymizer.cli import main

    main()
    assert capsys.readouterr().out == "[EMAIL]"


def test_cli_stdin() -> None:
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    r = subprocess.run(
        [sys.executable, "-m", "anonymizer.cli"],
        input="x@y.co\n",
        capture_output=True,
        text=True,
        cwd=ROOT,
        env=env,
    )
    assert r.returncode == 0, r.stderr
    assert r.stdout == "[EMAIL]\n"


def test_cli_file(tmp_path: Path) -> None:
    p = tmp_path / "t.txt"
    p.write_text("SSN 123-45-6789\n", encoding="utf-8")
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    r = subprocess.run(
        [sys.executable, "-m", "anonymizer.cli", str(p)],
        capture_output=True,
        text=True,
        cwd=ROOT,
        env=env,
    )
    assert r.returncode == 0, r.stderr
    assert "[SSN]" in r.stdout


def test_cli_main_with_file(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    p = tmp_path / "in.txt"
    p.write_text("EIN 12-3456789", encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["anonymize-prompt", str(p)])
    from anonymizer.cli import main

    main()
    assert capsys.readouterr().out == "EIN [EIN]"
