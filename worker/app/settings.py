from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel


class WorkerRuntime(BaseModel):
    worker_id: str
    control_bind_host: str
    control_bind_port: int
    coordinator_api_host: str
    coordinator_api_port: int
    work_root: str
    log_root: str
    poll_interval_seconds: int
    heartbeat_interval_seconds: int
    max_parallel_chunks: int


class ScannerRuntime(BaseModel):
    image: str
    network_mode: str
    user: str
    shm_size: str
    cap_add: list[str]
    work_mount_in_container: str
    engine_environment: dict[str, str]
    command_template: list[str]


class WorkerConfig(BaseModel):
    worker: WorkerRuntime
    scanner: ScannerRuntime


def load_settings() -> WorkerConfig:
    config_path = Path(os.environ.get("WORKER_CONFIG", "/app/config/worker.yml"))
    raw: dict[str, Any] = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    cfg = WorkerConfig(**raw)

    worker_id_override = os.environ.get("WORKER_ID")
    if worker_id_override:
        cfg.worker.worker_id = worker_id_override

    return cfg
