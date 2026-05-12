from __future__ import annotations

from pathlib import Path

import httpx


class CoordinatorClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.client = httpx.Client(timeout=120.0)

    def register_worker(self, worker_id: str) -> None:
        self.client.post(
            f"{self.base_url}/api/v1/workers/register",
            json={
                "worker_id": worker_id,
                "version": "1.0.0",
                "capabilities": {"scanner_engine": True},
                "capacity": {"scanner_engine": 1},
            },
        ).raise_for_status()

    def lease(self, worker_id: str) -> dict | None:
        resp = self.client.post(
            f"{self.base_url}/api/v1/workers/lease",
            json={"worker_id": worker_id},
        )
        resp.raise_for_status()
        return resp.json().get("chunk")

    def heartbeat(self, worker_id: str, chunk_id: str, progress: dict) -> bool:
        resp = self.client.post(
            f"{self.base_url}/api/v1/workers/heartbeat",
            json={
                "worker_id": worker_id,
                "chunk_id": chunk_id,
                "progress": progress,
            },
        )
        resp.raise_for_status()
        body = resp.json()
        if "chunk_lease_active" in body:
            return bool(body["chunk_lease_active"])
        return True

    def upload_artifacts(self, chunk_id: str, artifact_paths: list[Path]) -> list[dict]:
        files = []
        try:
            for path in artifact_paths:
                files.append(("files", (path.name, path.open("rb"), "application/octet-stream")))
            resp = self.client.post(f"{self.base_url}/api/v1/workers/upload-artifacts/{chunk_id}", files=files)
            resp.raise_for_status()
            return resp.json().get("artifacts", [])
        finally:
            for _, tpl in files:
                tpl[1].close()

    def complete(self, worker_id: str, chunk_id: str, metrics: dict, artifacts: list[dict]) -> None:
        self.client.post(
            f"{self.base_url}/api/v1/workers/complete",
            json={
                "worker_id": worker_id,
                "chunk_id": chunk_id,
                "status": "success",
                "metrics": metrics,
                "artifacts": artifacts,
            },
        ).raise_for_status()

    def fail(self, worker_id: str, chunk_id: str, error: str) -> None:
        self.client.post(
            f"{self.base_url}/api/v1/workers/fail",
            json={
                "worker_id": worker_id,
                "chunk_id": chunk_id,
                "status": "failed",
                "error": error,
            },
        ).raise_for_status()
