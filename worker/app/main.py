from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from threading import Event, Lock, Thread

from fastapi import FastAPI, HTTPException

from .chunk_runner import ChunkRunner
from .coordinator_client import CoordinatorClient
from .settings import load_settings

CFG = load_settings()
BASE_URL = f"http://{CFG.worker.coordinator_api_host}:{CFG.worker.coordinator_api_port}"
app = FastAPI(title="scanner-worker")


@dataclass
class RunningChunk:
    chunk: dict
    cancel_event: Event
    status: str
    thread_name: str


RUNNING: dict[str, RunningChunk] = {}
RUNNING_LOCK = Lock()
STOP_EVENT = Event()


def _heartbeat_loop(client: CoordinatorClient, worker_id: str, chunk_id: str, cancel_event: Event) -> None:
    while not cancel_event.wait(CFG.worker.heartbeat_interval_seconds):
        try:
            client.heartbeat(worker_id, chunk_id, {"state": "running"})
        except Exception:
            pass


def _execute_chunk(chunk: dict) -> None:
    client = CoordinatorClient(BASE_URL)
    runner = ChunkRunner(CFG)
    chunk_id = chunk["chunk_id"]
    cancel_event = Event()

    with RUNNING_LOCK:
        RUNNING[chunk_id] = RunningChunk(
            chunk=chunk,
            cancel_event=cancel_event,
            status="starting",
            thread_name=threading.current_thread().name,
        )

    hb = Thread(
        target=_heartbeat_loop,
        args=(client, CFG.worker.worker_id, chunk_id, cancel_event),
        daemon=True,
    )
    hb.start()

    try:
        with RUNNING_LOCK:
            RUNNING[chunk_id].status = "running"

        metrics, artifact_paths = runner.run_chunk(chunk, cancel_event)
        uploaded = client.upload_artifacts(chunk_id, artifact_paths)
        client.complete(CFG.worker.worker_id, chunk_id, metrics, uploaded)

        with RUNNING_LOCK:
            RUNNING[chunk_id].status = "done"

    except Exception as e:
        try:
            client.fail(CFG.worker.worker_id, chunk_id, str(e))
        except Exception:
            pass

        with RUNNING_LOCK:
            if chunk_id in RUNNING:
                RUNNING[chunk_id].status = f"failed: {e}"

    finally:
        cancel_event.set()
        time.sleep(1)
        with RUNNING_LOCK:
            RUNNING.pop(chunk_id, None)


def _lease_loop() -> None:
    client = CoordinatorClient(BASE_URL)

    while not STOP_EVENT.is_set():
        try:
            client.register_worker(CFG.worker.worker_id)

            with RUNNING_LOCK:
                if len(RUNNING) >= CFG.worker.max_parallel_chunks:
                    time.sleep(CFG.worker.poll_interval_seconds)
                    continue

            chunk = client.lease(CFG.worker.worker_id)
            if not chunk:
                time.sleep(CFG.worker.poll_interval_seconds)
                continue

            t = Thread(target=_execute_chunk, args=(chunk,), daemon=True)
            t.start()

        except Exception:
            time.sleep(CFG.worker.poll_interval_seconds)


@app.on_event("startup")
def startup() -> None:
    t = Thread(target=_lease_loop, daemon=True)
    t.start()


@app.get("/health")
def health() -> dict:
    with RUNNING_LOCK:
        return {
            "worker_id": CFG.worker.worker_id,
            "status": "ok",
            "running_chunks": len(RUNNING),
        }


@app.get("/chunks")
def chunks() -> dict:
    with RUNNING_LOCK:
        return {
            "worker_id": CFG.worker.worker_id,
            "running": [
                {
                    "chunk_id": k,
                    "status": v.status,
                    "scan_id": v.chunk.get("scan_id"),
                    "stage": v.chunk.get("stage"),
                }
                for k, v in RUNNING.items()
            ],
        }


@app.post("/chunks/{chunk_id}/cancel")
def cancel(chunk_id: str) -> dict:
    with RUNNING_LOCK:
        running = RUNNING.get(chunk_id)
        if not running:
            raise HTTPException(status_code=404, detail="chunk not running")
        running.cancel_event.set()
        running.status = "cancel-requested"

    return {
        "worker_id": CFG.worker.worker_id,
        "chunk_id": chunk_id,
        "status": "cancel-requested",
    }
