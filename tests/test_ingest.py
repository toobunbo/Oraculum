from __future__ import annotations

import json
from pathlib import Path

import pytest

from oraculum.cli.main import main
from oraculum.ingest.runner import IngestError, run_ingest


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _write_functions_csv(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(
            [
                '"name","file","start_line","end_line","scope"',
                '"outer","pkg/app.py",1,100,"Module pkg.app"',
                '"target","pkg/app.py",10,20,"Function outer"',
                '"fp_func","pkg/app.py",30,35,"Module pkg.app"',
                '"nmd_func","pkg/app.py",40,45,"Module pkg.app"',
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def _verdict_item(
    *,
    rule_id: str,
    line: int,
    verdict: str,
    file: str = "pkg/app.py",
) -> dict:
    return {
        "finding": {
            "rule_id": rule_id,
            "message": "demo finding",
            "file": file,
            "start_line": line,
            "end_line": line,
            "repo_name": "demo",
            "lang": "python",
            "sarif_path": "/tmp/demo.sarif",
            "tool": "CodeQL",
            "dataflow_path": [],
            "severity": "9.1",
            "precision": "high",
            "cwe_ids": [],
            "tags": [],
            "related_locations": [],
        },
        "verdict": verdict,
        "confidence": "High",
        "confidence_score": 0.95,
        "reasoning": "reason",
        "answers": ["answer"],
        "context_needed": [],
        "iterations": 1,
        "model": "glm-5.1",
        "timestamp": "2026-05-23T00:00:00",
        "elapsed_seconds": 1.0,
        "tokens_used": 10,
        "input_tokens": 7,
        "output_tokens": 3,
        "cached_input_tokens": 0,
        "cost_usd": 0.0,
        "data_flow": "source -> sink",
    }


def _make_vhx_fixture(tmp_path: Path) -> Path:
    vhx_root = tmp_path / "VulnHunterX"
    (vhx_root / "repos/python/demo/pkg").mkdir(parents=True)
    (vhx_root / "repos/python/demo/pkg/app.py").write_text(
        "def outer():\n"
        "    pass\n\n"
        "def target(value):\n"
        "    return value\n\n"
        "def fp_func(value):\n"
        "    return value\n\n"
        "def nmd_func(value):\n"
        "    return value\n",
        encoding="utf-8",
    )
    output_root = vhx_root / "output/python/demo"
    _write_functions_csv(output_root / "context/functions.csv")
    (output_root / "context/callers.csv").write_text("", encoding="utf-8")
    (output_root / "context/classes.csv").write_text("", encoding="utf-8")

    old_summary = {
        "timestamp": "2026-01-01T00:00:00",
        "verdicts": [_verdict_item(rule_id="py/old", line=12, verdict="True Positive")],
    }
    new_summary = {
        "timestamp": "2026-05-23T00:00:00",
        "verdicts": [
            _verdict_item(rule_id="py/xxe", line=12, verdict="True Positive"),
            _verdict_item(rule_id="py/path-injection", line=32, verdict="False Positive"),
            _verdict_item(rule_id="py/ssrf", line=42, verdict="Needs More Data"),
            _verdict_item(rule_id="py/error", line=12, verdict="Error"),
        ],
    }
    verification_dir = output_root / "verification_results"
    _write_json(verification_dir / "summary_demo_20260101_000000.json", old_summary)
    _write_json(verification_dir / "summary_demo_20260523_000000.json", new_summary)
    return vhx_root


def test_ingest_defaults_to_latest_summary_and_tp_filter(tmp_path: Path) -> None:
    vhx_root = _make_vhx_fixture(tmp_path)
    output_dir = tmp_path / "oraculum-output"

    result = run_ingest(
        vhx_root=vhx_root,
        repo="demo",
        output_dir=output_dir,
    )

    assert result.ok
    assert result.selected == 1
    assert result.enriched == 1
    assert result.skipped == 3

    summary = json.loads(result.summary_path.read_text(encoding="utf-8"))
    assert summary["source"]["summary_path"].endswith("summary_demo_20260523_000000.json")
    assert summary["findings"][0]["function_name"] == "target"

    artifact_path = Path(summary["findings"][0]["artifact"])
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    assert artifact["id"] == "0"
    assert artifact["rule_slug"] == "py_xxe"
    assert artifact["function"]["name"] == "target"
    assert "function_name" not in artifact["finding"]


def test_ingest_all_filter_skips_error(tmp_path: Path) -> None:
    vhx_root = _make_vhx_fixture(tmp_path)

    result = run_ingest(
        vhx_root=vhx_root,
        repo="demo",
        verdict_filter="all",
        output_dir=tmp_path / "output",
    )

    assert result.ok
    assert result.selected == 3
    assert result.enriched == 3
    assert result.skipped == 1


def test_ingest_explicit_summary_path(tmp_path: Path) -> None:
    vhx_root = _make_vhx_fixture(tmp_path)
    old_summary = vhx_root / "output/python/demo/verification_results/summary_demo_20260101_000000.json"

    result = run_ingest(
        vhx_root=vhx_root,
        repo="demo",
        summary=old_summary,
        output_dir=tmp_path / "output",
    )

    summary = json.loads(result.summary_path.read_text(encoding="utf-8"))
    assert summary["source"]["summary_path"] == str(old_summary.resolve())
    assert summary["findings"][0]["rule_id"] == "py/old"


def test_ingest_no_matching_function_records_error(tmp_path: Path) -> None:
    vhx_root = _make_vhx_fixture(tmp_path)
    summary_path = vhx_root / "output/python/demo/verification_results/summary_demo_20260523_000000.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["verdicts"][0]["finding"]["file"] = "pkg/missing.py"
    _write_json(summary_path, summary)

    result = run_ingest(
        vhx_root=vhx_root,
        repo="demo",
        output_dir=tmp_path / "output",
    )

    assert not result.ok
    ingest_summary = json.loads(result.summary_path.read_text(encoding="utf-8"))
    assert ingest_summary["counts"]["failed"] == 1
    assert ingest_summary["errors"][0]["file"] == "pkg/missing.py"
    assert "No enclosing function" in ingest_summary["errors"][0]["error"]


def test_ingest_missing_functions_csv_fails(tmp_path: Path) -> None:
    vhx_root = _make_vhx_fixture(tmp_path)
    (vhx_root / "output/python/demo/context/functions.csv").unlink()

    with pytest.raises(Exception, match="functions.csv not found"):
        run_ingest(vhx_root=vhx_root, repo="demo", output_dir=tmp_path / "output")


def test_ingest_existing_output_requires_force(tmp_path: Path) -> None:
    vhx_root = _make_vhx_fixture(tmp_path)
    output_dir = tmp_path / "output"

    run_ingest(vhx_root=vhx_root, repo="demo", output_dir=output_dir)
    with pytest.raises(IngestError, match="Use --force"):
        run_ingest(vhx_root=vhx_root, repo="demo", output_dir=output_dir)

    forced = run_ingest(vhx_root=vhx_root, repo="demo", output_dir=output_dir, force=True)
    assert forced.ok


def test_ingest_cli_smoke(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    vhx_root = _make_vhx_fixture(tmp_path)
    output_dir = tmp_path / "output"

    rc = main(
        [
            "ingest",
            "--vhx-root",
            str(vhx_root),
            "--repo",
            "demo",
            "--lang",
            "python",
            "--output-dir",
            str(output_dir),
        ]
    )

    captured = capsys.readouterr()
    assert rc == 0
    assert "Done. selected=1 enriched=1 skipped=3 failed=0" in captured.out
    assert (output_dir / "python/demo/oraculum/ingest/summary.json").is_file()


def test_ingest_cli_reads_vhx_root_from_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    vhx_root = _make_vhx_fixture(tmp_path)
    output_dir = tmp_path / "output"
    monkeypatch.setenv("ORACULUM_VHX_ROOT", str(vhx_root))

    rc = main(
        [
            "ingest",
            "--repo",
            "demo",
            "--lang",
            "python",
            "--output-dir",
            str(output_dir),
        ]
    )

    captured = capsys.readouterr()
    assert rc == 0
    assert f"VulnHunterX root: {vhx_root}" in captured.out
    assert (output_dir / "python/demo/oraculum/ingest/summary.json").is_file()


def test_ingest_cli_reads_vhx_root_from_dotenv(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    vhx_root = _make_vhx_fixture(tmp_path)
    output_dir = tmp_path / "output"
    workdir = tmp_path / "workspace"
    workdir.mkdir()
    (workdir / ".env").write_text(f"ORACULUM_VHX_ROOT={vhx_root}\n", encoding="utf-8")
    monkeypatch.delenv("ORACULUM_VHX_ROOT", raising=False)
    monkeypatch.delenv("VHX_ROOT", raising=False)
    monkeypatch.chdir(workdir)

    rc = main(
        [
            "ingest",
            "--repo",
            "demo",
            "--lang",
            "python",
            "--output-dir",
            str(output_dir),
        ]
    )

    captured = capsys.readouterr()
    assert rc == 0
    assert f"VulnHunterX root: {vhx_root}" in captured.out
    assert (output_dir / "python/demo/oraculum/ingest/summary.json").is_file()


def test_ingest_cli_missing_vhx_root_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("ORACULUM_VHX_ROOT", raising=False)
    monkeypatch.delenv("VHX_ROOT", raising=False)
    monkeypatch.chdir(tmp_path)

    rc = main(["ingest", "--repo", "demo", "--lang", "python"])

    captured = capsys.readouterr()
    assert rc == 1
    assert "Pass --vhx-root or set ORACULUM_VHX_ROOT" in captured.err
