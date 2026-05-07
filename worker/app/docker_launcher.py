from __future__ import annotations

import re
import subprocess
import time
from pathlib import Path
from threading import Event

from .settings import WorkerConfig


class DockerLauncher:
    def __init__(self, cfg: WorkerConfig):
        self.cfg = cfg

    @staticmethod
    def _sanitize_name(value: str) -> str:
        value = value.lower()
        value = re.sub(r"[^a-z0-9_.-]+", "-", value)
        return value[:120]

    def _kill_container(self, container_name: str) -> None:
        subprocess.run(["docker", "rm", "-f", container_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def run_scanner_chunk(self, chunk_dir: Path, chunk: dict, cancel_event: Event) -> None:
        scanner = self.cfg.scanner
        container_name = self._sanitize_name(f"scan-{chunk['chunk_id']}")
        self._kill_container(container_name)

        cmd = [
            "docker", "run", "--rm", "--name", container_name,
            "--network", scanner.network_mode,
            "--user", scanner.user,
            "--shm-size", scanner.shm_size,
            "-v", f"{chunk_dir}:{scanner.work_mount_in_container}",
        ]

        for cap in scanner.cap_add:
            cmd += ["--cap-add", cap]

        env_map = dict(scanner.engine_environment)
        env_map.update(
            {
                "SCAN_ID": chunk["scan_id"],
                "CHUNK_ID": chunk["chunk_id"],
                "STAGE": chunk["stage"],
                "CONFIG_FILE": f"{scanner.work_mount_in_container}/config.json",
                "INPUT_FILE": f"{scanner.work_mount_in_container}/input/targets.txt",
                "OUTPUT_DIR": f"{scanner.work_mount_in_container}/output",
                "METRICS_FILE": f"{scanner.work_mount_in_container}/output/metrics.json",
                "MANIFEST_FILE": f"{scanner.work_mount_in_container}/output/manifest.json",
            }
        )

        for k, v in env_map.items():
            cmd += ["-e", f"{k}={v}"]

        cmd.append(scanner.image)
        cmd.extend(scanner.command_template)

        stdout_path = chunk_dir / "logs" / "scanner.stdout.log"
        stderr_path = chunk_dir / "logs" / "scanner.stderr.log"
        stdout_path.parent.mkdir(parents=True, exist_ok=True)

        with stdout_path.open("w", encoding="utf-8") as out, stderr_path.open("w", encoding="utf-8") as err:
            proc = subprocess.Popen(cmd, stdout=out, stderr=err)

            while True:
                rc = proc.poll()
                if rc is not None:
                    if rc != 0:
                        raise RuntimeError(f"scanner container exited with rc={rc}")
                    break

                if cancel_event.is_set():
                    self._kill_container(container_name)
                    raise RuntimeError("chunk cancelled")

                time.sleep(1)
