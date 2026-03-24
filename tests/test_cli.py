from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


def test_cli_main_inprocess(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr("sys.argv", ["anonymize-prompt"])
    monkeypatch.setattr("sys.stdin", io.StringIO("x@y.co"))
    from anonymizer.cli import main

    main()
    assert capsys.readouterr().out == "[EMAIL_1]"


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
    assert r.stdout == "[EMAIL_1]\n"


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
    assert "[SSN_1]" in r.stdout


def test_cli_main_with_file(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    p = tmp_path / "in.txt"
    p.write_text("EIN 12-3456789", encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["anonymize-prompt", str(p)])
    from anonymizer.cli import main

    main()
    assert capsys.readouterr().out == "EIN [EIN_1]"


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
    assert capsys.readouterr().out == "Hello [PERSON_1]"


def test_cli_mapping_out_roundtrip(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    inp = tmp_path / "in.txt"
    inp.write_text("mail x@y.co ok", encoding="utf-8")
    map_path = tmp_path / "map.json"
    env = {**os.environ, "PYTHONPATH": str(repo_root / "src")}
    r = subprocess.run(
        [
            sys.executable,
            "-m",
            "anonymizer.cli",
            str(inp),
            "--mapping-out",
            str(map_path),
        ],
        capture_output=True,
        text=True,
        cwd=repo_root,
        env=env,
    )
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "mail [EMAIL_1] ok"
    data = json.loads(map_path.read_text(encoding="utf-8"))
    assert data["[EMAIL_1]"] == "x@y.co"

    red_path = tmp_path / "redacted.txt"
    red_path.write_text(r.stdout, encoding="utf-8")
    r2 = subprocess.run(
        [
            sys.executable,
            "-m",
            "anonymizer.cli",
            "--unredact",
            "--mapping",
            str(map_path),
            str(red_path),
        ],
        capture_output=True,
        text=True,
        cwd=repo_root,
        env=env,
    )
    assert r2.returncode == 0, r2.stderr
    assert r2.stdout == "mail x@y.co ok"


def test_cli_unredact_with_file_path(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    map_path = tmp_path / "m.json"
    map_path.write_text('{"[EMAIL_1]": "z@z.com"}', encoding="utf-8")
    red_path = tmp_path / "red.txt"
    red_path.write_text("Z [EMAIL_1]", encoding="utf-8")
    env = {**os.environ, "PYTHONPATH": str(repo_root / "src")}
    r = subprocess.run(
        [
            sys.executable,
            "-m",
            "anonymizer.cli",
            "--unredact",
            "--mapping",
            str(map_path),
            str(red_path),
        ],
        capture_output=True,
        text=True,
        cwd=repo_root,
        env=env,
    )
    assert r.returncode == 0, r.stderr
    assert r.stdout == "Z z@z.com"


def test_cli_unredact_requires_mapping(
    repo_root: Path,
) -> None:
    env = {**os.environ, "PYTHONPATH": str(repo_root / "src")}
    r = subprocess.run(
        [
            sys.executable,
            "-m",
            "anonymizer.cli",
            "--unredact",
        ],
        capture_output=True,
        text=True,
        cwd=repo_root,
        env=env,
    )
    assert r.returncode != 0


def test_cli_unredact_stdin(
    repo_root: Path,
    tmp_path: Path,
) -> None:
    map_path = tmp_path / "m.json"
    map_path.write_text(
        json.dumps({"[EMAIL_1]": "restore@me.com"}),
        encoding="utf-8",
    )
    env = {**os.environ, "PYTHONPATH": str(repo_root / "src")}
    r = subprocess.run(
        [
            sys.executable,
            "-m",
            "anonymizer.cli",
            "--unredact",
            "--mapping",
            str(map_path),
        ],
        input="Hi [EMAIL_1]",
        capture_output=True,
        text=True,
        cwd=repo_root,
        env=env,
    )
    assert r.returncode == 0, r.stderr
    assert r.stdout == "Hi restore@me.com"


def test_cli_unredact_missing_mapping_exits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("sys.argv", ["anonymize-prompt", "--unredact"])
    from anonymizer.cli import main

    with pytest.raises(SystemExit):
        main()


def test_cli_main_unredact_inprocess(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    mp = tmp_path / "m.json"
    mp.write_text('{"[X_1]": "secret"}', encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["anonymize-prompt", "--unredact", "--mapping", str(mp)])
    monkeypatch.setattr("sys.stdin", io.StringIO("Hi [X_1]"))
    from anonymizer.cli import main

    main()
    assert capsys.readouterr().out == "Hi secret"


def test_cli_main_unredact_file_inprocess(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    mp = tmp_path / "m.json"
    mp.write_text('{"[X_1]": "secret"}', encoding="utf-8")
    red = tmp_path / "r.txt"
    red.write_text("Z [X_1]", encoding="utf-8")
    monkeypatch.setattr(
        "sys.argv",
        ["anonymize-prompt", "--unredact", "--mapping", str(mp), str(red)],
    )
    from anonymizer.cli import main

    main()
    assert capsys.readouterr().out == "Z secret"


def test_cli_main_mapping_out_inprocess(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    out_path = tmp_path / "map.json"
    monkeypatch.setattr(
        "sys.argv",
        ["anonymize-prompt", "--mapping-out", str(out_path)],
    )
    monkeypatch.setattr("sys.stdin", io.StringIO("x@y.co"))
    from anonymizer.cli import main

    main()
    assert "x@y.co" in out_path.read_text(encoding="utf-8")


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
    assert "mapping" in r.stdout.lower()
