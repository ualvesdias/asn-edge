from __future__ import annotations

import json
from pathlib import Path
from threading import Event

from .docker_launcher import DockerLauncher
from .settings import WorkerConfig


class ChunkRunner:
    def __init__(self, cfg: WorkerConfig):
        self.cfg = cfg
        self.work_root = Path(cfg.worker.work_root)
        self.log_root = Path(cfg.worker.log_root)
        self.work_root.mkdir(parents=True, exist_ok=True)
        self.log_root.mkdir(parents=True, exist_ok=True)
        self.launcher = DockerLauncher(cfg)

    def _write_chunk_inputs(self, chunk_dir: Path, chunk: dict) -> None:
        (chunk_dir / "input").mkdir(parents=True, exist_ok=True)
        (chunk_dir / "output" / "raw").mkdir(parents=True, exist_ok=True)
        (chunk_dir / "logs").mkdir(parents=True, exist_ok=True)
        (chunk_dir / "run").mkdir(parents=True, exist_ok=True)

        targets = chunk["payload"].get("targets", [])
        (chunk_dir / "input" / "targets.txt").write_text(
            "\n".join(targets) + ("\n" if targets else ""),
            encoding="utf-8",
        )

        (chunk_dir / "input" / "metadata.json").write_text(
            json.dumps(
                {
                    "scan_id": chunk["scan_id"],
                    "chunk_id": chunk["chunk_id"],
                    "stage": chunk["stage"],
                    "payload": chunk["payload"],
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        stage_cfg = {
            "engine_mode": "chunk",
            "stage": chunk["stage"],
            "input_file": "/work/input/targets.txt",
            "output_dir": "/work/output",
            "metrics_file": "/work/output/metrics.json",
            "manifest_file": "/work/output/manifest.json",
        }

        (chunk_dir / "config.json").write_text(
            json.dumps(stage_cfg, indent=2),
            encoding="utf-8",
        )

    def _collect_metrics_and_artifacts(self, chunk_dir: Path) -> tuple[dict, list[Path]]:
        output_dir = chunk_dir / "output"
        metrics_path = output_dir / "metrics.json"
        metrics = {}

        if metrics_path.exists():
            metrics = json.loads(metrics_path.read_text(encoding="utf-8"))

        artifact_paths = []
        for path in output_dir.rglob("*"):
            if path.is_file() and path.suffix.lower() in {".jsonl", ".json", ".html", ".png", ".jpg", ".jpeg"}:
                artifact_paths.append(path)

        return metrics, artifact_paths

    def run_chunk(self, chunk: dict, cancel_event: Event) -> tuple[dict, list[Path]]:
        chunk_dir = self.work_root / chunk["chunk_id"]
        chunk_dir.mkdir(parents=True, exist_ok=True)

        self._write_chunk_inputs(chunk_dir, chunk)
        self.launcher.run_scanner_chunk(chunk_dir, chunk, cancel_event)
        return self._collect_metrics_and_artifacts(chunk_dir)
