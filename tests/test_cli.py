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


def test_cli_stdin(repo_root: Path) -> None:
    env = {**os.environ, "PYTHONPATH": str(repo_root / "src")}
    r = subprocess.run(
        [sys.executable, "-m", "anonymizer.cli"],
        input="x@y.co\n",
        capture_output=True,
        text=True,
        cwd=repo_root,
        env=env,
    )
    assert r.returncode == 0, r.stderr
    assert r.stdout == "[EMAIL]\n"


def test_cli_file(repo_root: Path, tmp_path: Path) -> None:
    p = tmp_path / "t.txt"
    p.write_text("SSN 123-45-6789\n", encoding="utf-8")
    env = {**os.environ, "PYTHONPATH": str(repo_root / "src")}
    r = subprocess.run(
        [sys.executable, "-m", "anonymizer.cli", str(p)],
        capture_output=True,
        text=True,
        cwd=repo_root,
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


def test_cli_with_config_file(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    cfg_path = tmp_path / "cfg.yaml"
    cfg_path.write_text(
        'people:\n  - "Secret Name"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr("sys.argv", ["anonymize-prompt", "-c", str(cfg_path)])
    monkeypatch.setattr("sys.stdin", io.StringIO("Hello Secret Name"))
    from anonymizer.cli import main

    main()
    assert capsys.readouterr().out == "Hello [PERSON]"


def test_cli_help(repo_root: Path) -> None:
    env = {**os.environ, "PYTHONPATH": str(repo_root / "src")}
    r = subprocess.run(
        [sys.executable, "-m", "anonymizer.cli", "--help"],
        capture_output=True,
        text=True,
        cwd=repo_root,
        env=env,
    )
    assert r.returncode == 0
    assert "anonymize-prompt" in r.stdout or "Redact" in r.stdout
