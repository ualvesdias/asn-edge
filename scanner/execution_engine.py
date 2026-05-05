from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class EngineConfig:
    stage: str
    input_file: Path
    output_dir: Path
    metrics_file: Path
    manifest_file: Path
    scan_id: str
    chunk_id: str


def _env_or(default: str, key: str) -> str:
    return os.environ.get(key, default)


def load_engine_config() -> EngineConfig:
    config_file = Path(os.environ["CONFIG_FILE"])
    cfg = json.loads(config_file.read_text(encoding="utf-8")) if config_file.exists() else {}

    output_dir = Path(os.environ.get("OUTPUT_DIR", cfg.get("output_dir", "/work/output")))
    metrics_file = Path(os.environ.get("METRICS_FILE", cfg.get("metrics_file", str(output_dir / "metrics.json"))))
    manifest_file = Path(os.environ.get("MANIFEST_FILE", cfg.get("manifest_file", str(output_dir / "manifest.json"))))

    return EngineConfig(
        stage=os.environ.get("STAGE", cfg.get("stage", "")).lower(),
        input_file=Path(os.environ.get("INPUT_FILE", cfg.get("input_file", "/work/input/targets.txt"))),
        output_dir=output_dir,
        metrics_file=metrics_file,
        manifest_file=manifest_file,
        scan_id=os.environ.get("SCAN_ID", ""),
        chunk_id=os.environ.get("CHUNK_ID", ""),
    )


def _read_targets(path: Path) -> list[str]:
    if not path.exists():
        raise RuntimeError(f"input file not found: {path}")
    return [x.strip() for x in path.read_text(encoding="utf-8", errors="ignore").splitlines() if x.strip()]


def _run_to_file(cmd: list[str], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as out:
        proc = subprocess.run(cmd, stdout=out, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"command failed ({proc.returncode}): {' '.join(cmd)}\n{proc.stderr}")


def _count_lines(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for _ in path.open("r", encoding="utf-8", errors="ignore"))


def run_naabu(cfg: EngineConfig, targets: list[str]) -> dict:
    out = cfg.output_dir / "raw" / "naabu.jsonl"
    cmd = [
        "naabu",
        "-json",
        "-list", str(cfg.input_file),
        "-top-ports", _env_or("100", "ENGINE_NAABU_TOP_PORTS"),
        "-rate", _env_or("300", "ENGINE_NAABU_RATE"),
    ]
    if os.environ.get("ENGINE_NAABU_SCAN_TYPE"):
        cmd += ["-scan-type", os.environ["ENGINE_NAABU_SCAN_TYPE"]]
    if os.environ.get("ENGINE_NAABU_EXCLUDE_CDN", "1") == "1":
        cmd += ["-exclude-cdn"]
    _run_to_file(cmd, out)
    return {"targets": len(targets), "records": _count_lines(out), "artifact": str(out)}


def run_httpx(cfg: EngineConfig, targets: list[str]) -> dict:
    out = cfg.output_dir / "raw" / "httpx.jsonl"
    cmd = [
        "httpx",
        "-json",
        "-l", str(cfg.input_file),
        "-sc",
        "-title",
        "-server",
        "-td",
        "-jarm",
        "-tls-grab",
        "-asn",
    ]
    _run_to_file(cmd, out)
    return {"targets": len(targets), "records": _count_lines(out), "artifact": str(out)}


def run_tlsx(cfg: EngineConfig, targets: list[str]) -> dict:
    out = cfg.output_dir / "raw" / "tlsx.jsonl"
    cmd = ["tlsx", "-j", "-silent", "-l", str(cfg.input_file)]
    _run_to_file(cmd, out)
    return {"targets": len(targets), "records": _count_lines(out), "artifact": str(out)}


def run_katana(cfg: EngineConfig, targets: list[str]) -> dict:
    out = cfg.output_dir / "raw" / "katana.jsonl"
    cmd = [
        "katana",
        "-list", str(cfg.input_file),
        "-d", _env_or("2", "ENGINE_KATANA_DEPTH"),
        "-jsonl",
        "-or",
        "-ob",
    ]
    _run_to_file(cmd, out)
    return {"targets": len(targets), "records": _count_lines(out), "artifact": str(out)}


def run_nuclei(cfg: EngineConfig, targets: list[str]) -> dict:
    out = cfg.output_dir / "raw" / "nuclei.jsonl"
    cmd = [
        "nuclei",
        "-l", str(cfg.input_file),
        "-severity", _env_or("critical,high,medium", "ENGINE_NUCLEI_SEVERITY"),
        "-rl", _env_or("50", "ENGINE_NUCLEI_RATE_LIMIT"),
        "-jle", str(out),
        "-silent",
    ]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"command failed ({proc.returncode}): {' '.join(cmd)}\n{proc.stderr}")
    return {"targets": len(targets), "records": _count_lines(out), "artifact": str(out)}


def run_chunk_engine_mode() -> int:
    cfg = load_engine_config()
    cfg.output_dir.mkdir(parents=True, exist_ok=True)
    (cfg.output_dir / "raw").mkdir(parents=True, exist_ok=True)

    targets = _read_targets(cfg.input_file)

    if cfg.stage not in {"naabu", "httpx", "tlsx", "katana", "nuclei"}:
        raise RuntimeError(f"unsupported engine stage: {cfg.stage}")

    runners = {
        "naabu": run_naabu,
        "httpx": run_httpx,
        "tlsx": run_tlsx,
        "katana": run_katana,
        "nuclei": run_nuclei,
    }

    metrics = runners[cfg.stage](cfg, targets)
    metrics.update(
        {
            "scan_id": cfg.scan_id,
            "chunk_id": cfg.chunk_id,
            "stage": cfg.stage,
        }
    )

    cfg.metrics_file.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    cfg.manifest_file.write_text(
        json.dumps(
            {
                "scan_id": cfg.scan_id,
                "chunk_id": cfg.chunk_id,
                "stage": cfg.stage,
                "status": "success",
                "metrics_file": str(cfg.metrics_file),
                "artifacts": [metrics.get("artifact")],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return 0


def maybe_run_chunk_engine_mode() -> bool:
    if os.environ.get("ENGINE_MODE") != "chunk":
        return False
    raise SystemExit(run_chunk_engine_mode())
