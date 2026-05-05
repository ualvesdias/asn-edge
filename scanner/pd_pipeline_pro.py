#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import dataclasses
import hashlib
import html
import json
import logging
import os
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from execution_engine import maybe_run_chunk_engine_mode

# =========================
# Configuration
# =========================


@dataclass
class PipelineConfig:
    asn_file: str
    output_root: str = "./pd_runs"

    # Tool bootstrap
    pdtm_bin: str = "pdtm"
    auto_install_missing_tools: bool = False
    auto_update_tools: bool = False

    # Generic execution
    retries: int = 2
    retry_backoff_sec: float = 5.0
    log_level: str = "INFO"
    force: bool = False

    # Tool paths
    naabu_bin: str = "naabu"
    dnsx_bin: str = "dnsx"
    httpx_bin: str = "httpx"
    tlsx_bin: str = "tlsx"
    katana_bin: str = "katana"
    nuclei_bin: str = "nuclei"

    # Stage timeouts
    naabu_timeout_sec: int = 21600
    dnsx_timeout_sec: int = 3600
    httpx_timeout_sec: int = 21600
    screenshots_timeout_sec: int = 7200
    tlsx_timeout_sec: int = 7200
    katana_timeout_sec: int = 21600
    nuclei_timeout_sec: int = 43200

    # naabu
    naabu_top_ports: int = 1000
    naabu_rate: int = 1000

    # httpx
    httpx_threads: int = 50
    httpx_rate_limit: int = 150
    httpx_store_responses: bool = True
    httpx_system_chrome: bool = False
    httpx_screenshot_limit_per_asn: int = 80
    httpx_screenshot_timeout_seconds: int = 10

    # katana
    katana_enabled: bool = True
    katana_depth: int = 3
    katana_known_files: str = "robotstxt,sitemapxml"
    katana_crawl_duration: str = "10m"
    katana_max_response_size: int = 1_048_576
    katana_request_timeout_seconds: int = 10
    katana_retry: int = 1

    # nuclei
    nuclei_enabled: bool = True
    nuclei_severity: list[str] = field(
        default_factory=lambda: ["critical", "high", "medium"]
    )
    nuclei_rate_limit: int = 100
    nuclei_bulk_size: int = 25
    nuclei_concurrency: int = 25
    nuclei_request_timeout_seconds: int = 10
    nuclei_request_retries: int = 1
    nuclei_exclude_tags: list[str] = field(
        default_factory=lambda: ["dos", "bruteforce"]
    )
    nuclei_redact_keys: list[str] = field(
        default_factory=lambda: ["Authorization", "Cookie", "Set-Cookie", "X-Api-Key"]
    )
    nuclei_include_request_response: bool = False
    nuclei_extra_args: list[str] = field(default_factory=list)

    bgp_mrt_sources: list[dict[str, str]] = field(default_factory=list)
    bgp_cache_dir: str = "./state/bgp-cache"

    history_db_path: str = "./state/history.sqlite3"
    diff_max_items: int = 200

    interesting_ports: list[int] = field(
        default_factory=lambda: [
            21,
            22,
            23,
            25,
            53,
            110,
            143,
            445,
            465,
            587,
            993,
            995,
            1433,
            1521,
            2375,
            2376,
            3000,
            3306,
            3389,
            5000,
            5432,
            5601,
            5900,
            6379,
            6443,
            8080,
            8443,
            9000,
            9200,
            9300,
            11211,
            27017,
        ]
    )
    interesting_title_regex: str = (
        r"(admin|login|jenkins|grafana|kibana|prometheus|vpn|dashboard|"
        r"gitlab|jira|confluence|harbor|argocd|rabbitmq|sonarqube)"
    )
    interesting_tech_regex: str = (
        r"(jenkins|grafana|kibana|prometheus|gitlab|jira|confluence|"
        r"harbor|argocd|rabbitmq|sonarqube|kubernetes|docker)"
    )

    @classmethod
    def from_json(cls, path: str | Path) -> "PipelineConfig":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(**raw)


# =========================
# Utility
# =========================


def lookup_prefixes_for_asn(db_path: Path, asn: str) -> list[str]:
    asn_num = asn.strip().upper()
    if asn_num.startswith("AS"):
        asn_num = asn_num[2:]

    if not db_path.exists():
        raise RuntimeError(f"ASN prefix DB not found: {db_path}")

    conn = sqlite3.connect(str(db_path))
    try:
        rows = conn.execute(
            "SELECT prefix FROM current_asn_prefixes WHERE asn=? ORDER BY prefix",
            (asn_num,),
        ).fetchall()
        return [row[0] for row in rows]
    finally:
        conn.close()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()


def stable_json_hash(obj: Any) -> str:
    return sha256_text(
        json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    )


def canonical_url(url: str) -> str:
    try:
        p = urlparse(url.strip())
        scheme = (p.scheme or "http").lower()
        host = (p.hostname or "").lower()
        if not host:
            return url.strip()
        port = p.port or (443 if scheme == "https" else 80)
        path = p.path or "/"
        if len(path) > 1:
            path = path.rstrip("/") or "/"
        return f"{scheme}://{host}:{port}{path}"
    except Exception:
        return url.strip()


def canonical_target(target: str) -> str:
    target = target.strip()
    if not target:
        return ""
    if target.startswith(("http://", "https://")):
        return canonical_url(target)
    return target.lower()


def json_load_file(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_lines(path: Path, lines: Iterable[str]) -> None:
    uniq = sorted({x.strip() for x in lines if x and x.strip()})
    write_text(path, "\n".join(uniq) + ("\n" if uniq else ""))


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [
        x.strip()
        for x in path.read_text(encoding="utf-8", errors="ignore").splitlines()
        if x.strip()
    ]


def touch_empty(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text("", encoding="utf-8")


def iter_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    if not path.exists():
        return
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return list(iter_jsonl(path))


def json_dump_file(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")


def parse_url_hostport(url: str) -> str | None:
    try:
        p = urlparse(url)
        if not p.scheme or not p.hostname:
            return None
        port = p.port
        if port is None:
            port = 443 if p.scheme == "https" else 80
        return f"{p.hostname}:{port}"
    except Exception:
        return None


def get_httpx_url(row: dict[str, Any]) -> str | None:
    for key in ("url", "final_url", "input"):
        v = row.get(key)
        if isinstance(v, str) and v.strip().startswith(("http://", "https://")):
            return v.strip()
    host = row.get("host") or row.get("input")
    scheme = row.get("scheme")
    port = row.get("port")
    if host and scheme:
        if port:
            return f"{scheme}://{host}:{port}"
        return f"{scheme}://{host}"
    return None


def get_httpx_status(row: dict[str, Any]) -> int | None:
    for key in ("status-code", "status_code", "status"):
        v = row.get(key)
        if isinstance(v, int):
            return v
        if isinstance(v, str) and v.isdigit():
            return int(v)
    return None


def get_httpx_title(row: dict[str, Any]) -> str:
    v = row.get("title")
    return v if isinstance(v, str) else ""


def get_httpx_server(row: dict[str, Any]) -> str:
    for key in ("webserver", "web-server", "server"):
        v = row.get(key)
        if isinstance(v, str):
            return v
    return ""


def get_httpx_tech(row: dict[str, Any]) -> list[str]:
    for key in ("tech", "technologies"):
        v = row.get(key)
        if isinstance(v, list):
            return [str(x) for x in v if str(x).strip()]
        if isinstance(v, str) and v.strip():
            return [v.strip()]
    return []


def get_httpx_asn(row: dict[str, Any]) -> str:
    v = row.get("asn")
    if isinstance(v, dict):
        name = v.get("as-name") or v.get("name") or ""
        asn_no = v.get("as-number") or v.get("asn") or ""
        if asn_no and name:
            return f"{asn_no} {name}".strip()
        return str(name or asn_no)
    if isinstance(v, str):
        return v
    return ""


def get_httpx_cdn(row: dict[str, Any]) -> str:
    v = row.get("cdn")
    if isinstance(v, str):
        return v
    v2 = row.get("cdn_name")
    if isinstance(v2, str):
        return v2
    return ""


def severity_weight(sev: str) -> int:
    return {
        "critical": 100,
        "high": 70,
        "medium": 40,
        "low": 15,
        "info": 5,
        "unknown": 1,
    }.get(str(sev).lower(), 1)


def sizeof_fmt(num: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if num < 1024:
            return f"{num:.1f} {unit}" if unit != "B" else f"{num} {unit}"
        num /= 1024
    return f"{num:.1f} PB"


def asn_to_num(value: str) -> str:
    value = value.strip().upper()
    return value.removeprefix("AS")


def enum_value(value: Any) -> Any:
    if isinstance(value, (int, str)):
        return value
    try:
        return list(value)[0]
    except Exception:
        return value


def flatten_as_path_segments(value: Any) -> list[str]:
    out: list[str] = []
    if not isinstance(value, list):
        return out

    for seg in value:
        seg_value = seg.get("value", [])
        if isinstance(seg_value, list):
            for item in seg_value:
                s = str(item).strip()
                if s.isdigit():
                    out.append(s)
        else:
            s = str(seg_value).strip()
            if s.isdigit():
                out.append(s)
    return out


# =========================
# State DB
# =========================


class StateDB:
    def __init__(self, path: Path):
        self.path = path
        self.conn = sqlite3.connect(str(path))
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS run_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS stages (
                asn TEXT NOT NULL,
                stage TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT,
                ended_at TEXT,
                attempts INTEGER NOT NULL DEFAULT 0,
                cmd_json TEXT,
                stdout_path TEXT,
                stderr_path TEXT,
                note TEXT,
                metrics_json TEXT,
                PRIMARY KEY (asn, stage)
            );
            """
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def set_meta(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT INTO run_meta(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
        self.conn.commit()

    def get_meta(self, key: str) -> str | None:
        row = self.conn.execute(
            "SELECT value FROM run_meta WHERE key=?", (key,)
        ).fetchone()
        return row[0] if row else None

    def get_stage(self, asn: str, stage: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            """
            SELECT asn, stage, status, started_at, ended_at, attempts, cmd_json,
                   stdout_path, stderr_path, note, metrics_json
            FROM stages WHERE asn=? AND stage=?
            """,
            (asn, stage),
        ).fetchone()
        if not row:
            return None
        keys = [
            "asn",
            "stage",
            "status",
            "started_at",
            "ended_at",
            "attempts",
            "cmd_json",
            "stdout_path",
            "stderr_path",
            "note",
            "metrics_json",
        ]
        return dict(zip(keys, row))

    def begin_stage(
        self,
        asn: str,
        stage: str,
        cmd: list[str] | None,
        stdout_path: Path,
        stderr_path: Path,
    ) -> None:
        prev = self.get_stage(asn, stage)
        attempts = (prev["attempts"] if prev else 0) + 1
        self.conn.execute(
            """
            INSERT INTO stages(asn, stage, status, started_at, ended_at, attempts, cmd_json,
                               stdout_path, stderr_path, note, metrics_json)
            VALUES(?, ?, 'running', ?, NULL, ?, ?, ?, ?, '', '')
            ON CONFLICT(asn, stage) DO UPDATE SET
                status='running',
                started_at=excluded.started_at,
                ended_at=NULL,
                attempts=?,
                cmd_json=excluded.cmd_json,
                stdout_path=excluded.stdout_path,
                stderr_path=excluded.stderr_path,
                note='',
                metrics_json=''
            """,
            (
                asn,
                stage,
                utc_now(),
                attempts,
                json.dumps(cmd or []),
                str(stdout_path),
                str(stderr_path),
                attempts,
            ),
        )
        self.conn.commit()

    def end_stage(
        self,
        asn: str,
        stage: str,
        status: str,
        note: str = "",
        metrics: dict[str, Any] | None = None,
    ) -> None:
        self.conn.execute(
            """
            UPDATE stages
            SET status=?, ended_at=?, note=?, metrics_json=?
            WHERE asn=? AND stage=?
            """,
            (
                status,
                utc_now(),
                note,
                json.dumps(metrics or {}, ensure_ascii=False),
                asn,
                stage,
            ),
        )
        self.conn.commit()


# =========================
# HistoryDB
# =========================


class HistoryDB:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(path))
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                run_dir TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS assets (
                asset_key TEXT PRIMARY KEY,
                asset_type TEXT NOT NULL,
                first_seen_run TEXT NOT NULL,
                first_seen_at TEXT NOT NULL,
                last_seen_run TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                times_seen INTEGER NOT NULL DEFAULT 0,
                last_json TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS asset_runs (
                run_id TEXT NOT NULL,
                asset_key TEXT NOT NULL,
                asn TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                interest_score INTEGER NOT NULL DEFAULT 0,
                interest_reason TEXT NOT NULL DEFAULT '',
                json TEXT NOT NULL,
                PRIMARY KEY (run_id, asset_key)
            );

            CREATE INDEX IF NOT EXISTS idx_asset_runs_run_id ON asset_runs(run_id);
            CREATE INDEX IF NOT EXISTS idx_asset_runs_asset_key ON asset_runs(asset_key);

            CREATE TABLE IF NOT EXISTS findings (
                finding_key TEXT PRIMARY KEY,
                template_id TEXT NOT NULL,
                name TEXT NOT NULL,
                first_seen_run TEXT NOT NULL,
                first_seen_at TEXT NOT NULL,
                last_seen_run TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                times_seen INTEGER NOT NULL DEFAULT 0,
                max_severity_weight INTEGER NOT NULL DEFAULT 0,
                last_json TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS finding_runs (
                run_id TEXT NOT NULL,
                finding_key TEXT NOT NULL,
                asn TEXT NOT NULL,
                severity TEXT NOT NULL,
                severity_weight INTEGER NOT NULL DEFAULT 0,
                json TEXT NOT NULL,
                PRIMARY KEY (run_id, finding_key)
            );

            CREATE INDEX IF NOT EXISTS idx_finding_runs_run_id ON finding_runs(run_id);
            CREATE INDEX IF NOT EXISTS idx_finding_runs_finding_key ON finding_runs(finding_key);
            """
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def ensure_run(self, run_id: str, started_at: str, run_dir: str) -> None:
        self.conn.execute(
            """
            INSERT INTO runs(run_id, started_at, finished_at, run_dir)
            VALUES(?, ?, NULL, ?)
            ON CONFLICT(run_id) DO UPDATE SET
                started_at=excluded.started_at,
                run_dir=excluded.run_dir
            """,
            (run_id, started_at, run_dir),
        )
        self.conn.commit()

    def finish_run(self, run_id: str, finished_at: str) -> None:
        self.conn.execute(
            "UPDATE runs SET finished_at=? WHERE run_id=?",
            (finished_at, run_id),
        )
        self.conn.commit()

    def previous_run(self, current_run_id: str, current_started_at: str) -> str | None:
        row = self.conn.execute(
            """
            SELECT run_id
            FROM runs
            WHERE started_at < ?
               OR (started_at = ? AND run_id != ?)
            ORDER BY started_at DESC, run_id DESC
            LIMIT 1
            """,
            (current_started_at, current_started_at, current_run_id),
        ).fetchone()
        return row[0] if row else None

    def seen_asset_keys_before(self, started_at: str) -> set[str]:
        rows = self.conn.execute(
            """
            SELECT DISTINCT ar.asset_key
            FROM asset_runs ar
            JOIN runs r ON r.run_id = ar.run_id
            WHERE r.started_at < ?
            """,
            (started_at,),
        ).fetchall()
        return {row[0] for row in rows}

    def seen_finding_keys_before(self, started_at: str) -> set[str]:
        rows = self.conn.execute(
            """
            SELECT DISTINCT fr.finding_key
            FROM finding_runs fr
            JOIN runs r ON r.run_id = fr.run_id
            WHERE r.started_at < ?
            """,
            (started_at,),
        ).fetchall()
        return {row[0] for row in rows}

    def asset_records_for_run(self, run_id: str | None) -> dict[str, dict[str, Any]]:
        if not run_id:
            return {}
        rows = self.conn.execute(
            """
            SELECT asset_key, interest_score, interest_reason, json
            FROM asset_runs
            WHERE run_id=?
            """,
            (run_id,),
        ).fetchall()
        out: dict[str, dict[str, Any]] = {}
        for asset_key, interest_score, interest_reason, js in rows:
            try:
                item = json.loads(js)
            except Exception:
                item = {}
            item["interest_score"] = int(interest_score or 0)
            item["interest_reason"] = interest_reason or ""
            out[asset_key] = item
        return out

    def finding_records_for_run(self, run_id: str | None) -> dict[str, dict[str, Any]]:
        if not run_id:
            return {}
        rows = self.conn.execute(
            """
            SELECT finding_key, severity, severity_weight, json
            FROM finding_runs
            WHERE run_id=?
            """,
            (run_id,),
        ).fetchall()
        out: dict[str, dict[str, Any]] = {}
        for finding_key, severity, severity_weight, js in rows:
            try:
                item = json.loads(js)
            except Exception:
                item = {}
            item["severity"] = severity or item.get("severity", "unknown")
            item["severity_weight"] = int(severity_weight or 0)
            out[finding_key] = item
        return out

    def upsert_assets(
        self, run_id: str, assets: list[dict[str, Any]], seen_at: str
    ) -> None:
        for asset in assets:
            asset_key = asset["asset_key"]
            asset_type = asset["asset_type"]
            payload = json.dumps(asset, sort_keys=True, ensure_ascii=False)

            existing = self.conn.execute(
                "SELECT asset_key FROM assets WHERE asset_key=?",
                (asset_key,),
            ).fetchone()

            if existing:
                self.conn.execute(
                    """
                    UPDATE assets
                    SET last_seen_run=?,
                        last_seen_at=?,
                        times_seen=times_seen+1,
                        last_json=?
                    WHERE asset_key=?
                    """,
                    (run_id, seen_at, payload, asset_key),
                )
            else:
                self.conn.execute(
                    """
                    INSERT INTO assets(
                        asset_key, asset_type,
                        first_seen_run, first_seen_at,
                        last_seen_run, last_seen_at,
                        times_seen, last_json
                    )
                    VALUES(?, ?, ?, ?, ?, ?, 1, ?)
                    """,
                    (asset_key, asset_type, run_id, seen_at, run_id, seen_at, payload),
                )

            self.conn.execute(
                """
                INSERT OR REPLACE INTO asset_runs(
                    run_id, asset_key, asn, fingerprint,
                    interest_score, interest_reason, json
                )
                VALUES(?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    asset_key,
                    asset.get("asn", ""),
                    asset.get("fingerprint", ""),
                    int(asset.get("interest_score", 0)),
                    asset.get("interest_reason", ""),
                    payload,
                ),
            )
        self.conn.commit()

    def upsert_findings(
        self, run_id: str, findings: list[dict[str, Any]], seen_at: str
    ) -> None:
        for finding in findings:
            finding_key = finding["finding_key"]
            template_id = finding.get("template_id", "")
            name = finding.get("name", "")
            sev_weight = int(finding.get("severity_weight", 0))
            payload = json.dumps(finding, sort_keys=True, ensure_ascii=False)

            existing = self.conn.execute(
                """
                SELECT max_severity_weight
                FROM findings
                WHERE finding_key=?
                """,
                (finding_key,),
            ).fetchone()

            if existing:
                max_weight = max(int(existing[0] or 0), sev_weight)
                self.conn.execute(
                    """
                    UPDATE findings
                    SET last_seen_run=?,
                        last_seen_at=?,
                        times_seen=times_seen+1,
                        max_severity_weight=?,
                        last_json=?
                    WHERE finding_key=?
                    """,
                    (run_id, seen_at, max_weight, payload, finding_key),
                )
            else:
                self.conn.execute(
                    """
                    INSERT INTO findings(
                        finding_key, template_id, name,
                        first_seen_run, first_seen_at,
                        last_seen_run, last_seen_at,
                        times_seen, max_severity_weight, last_json
                    )
                    VALUES(?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                    """,
                    (
                        finding_key,
                        template_id,
                        name,
                        run_id,
                        seen_at,
                        run_id,
                        seen_at,
                        sev_weight,
                        payload,
                    ),
                )

            self.conn.execute(
                """
                INSERT OR REPLACE INTO finding_runs(
                    run_id, finding_key, asn, severity, severity_weight, json
                )
                VALUES(?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    finding_key,
                    finding.get("asn", ""),
                    finding.get("severity", "unknown"),
                    sev_weight,
                    payload,
                ),
            )
        self.conn.commit()


# =========================
# Lock
# =========================


class FileLock:
    def __init__(self, path: Path):
        self.path = path
        self.fd: int | None = None

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        self.fd = os.open(str(self.path), flags)
        os.write(self.fd, f"{os.getpid()}\n".encode())

    def release(self) -> None:
        with contextlib.suppress(Exception):
            if self.fd is not None:
                os.close(self.fd)
        with contextlib.suppress(Exception):
            self.path.unlink()

    def __enter__(self) -> "FileLock":
        self.acquire()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.release()


# =========================
# Command runner
# =========================


class PipelineError(RuntimeError):
    pass


class CommandRunner:
    def __init__(self, retries: int, backoff_sec: float, logger: logging.Logger):
        self.retries = retries
        self.backoff_sec = backoff_sec
        self.log = logger

    def run(
        self,
        cmd: list[str],
        stdout_file: Path,
        stderr_file: Path,
        *,
        stdin_text: str | None = None,
        timeout_sec: int | None = None,
        cwd: Path | None = None,
    ) -> None:
        stdout_file.parent.mkdir(parents=True, exist_ok=True)
        stderr_file.parent.mkdir(parents=True, exist_ok=True)

        last_err: Exception | None = None

        for attempt in range(1, self.retries + 2):
            if attempt > 1:
                delay = self.backoff_sec * (attempt - 1)
                self.log.warning(
                    "Retry %s/%s after %.1fs: %s",
                    attempt - 1,
                    self.retries,
                    delay,
                    " ".join(cmd),
                )
                time.sleep(delay)

            with (
                stdout_file.open("w", encoding="utf-8") as out,
                stderr_file.open("a", encoding="utf-8") as err,
            ):
                err.write(f"\n[{utc_now()}] CMD: {' '.join(cmd)}\n")

                start_new_session = os.name != "nt"
                proc = subprocess.Popen(
                    cmd,
                    stdin=subprocess.PIPE if stdin_text is not None else None,
                    stdout=out,
                    stderr=err,
                    text=True,
                    cwd=str(cwd) if cwd else None,
                    start_new_session=start_new_session,
                )

                try:
                    proc.communicate(stdin_text, timeout=timeout_sec)
                    if proc.returncode == 0:
                        return
                    last_err = PipelineError(
                        f"command exited with rc={proc.returncode}: {' '.join(cmd)}"
                    )
                except subprocess.TimeoutExpired as e:
                    last_err = PipelineError(
                        f"timeout after {timeout_sec}s: {' '.join(cmd)}"
                    )
                    self._terminate(proc)
                except Exception as e:
                    last_err = e
                    self._terminate(proc)

        raise last_err or PipelineError("unknown command failure")

    @staticmethod
    def _terminate(proc: subprocess.Popen) -> None:
        with contextlib.suppress(Exception):
            if os.name != "nt":
                os.killpg(proc.pid, signal.SIGTERM)
                time.sleep(1)
                if proc.poll() is None:
                    os.killpg(proc.pid, signal.SIGKILL)
            else:
                proc.terminate()
                time.sleep(1)
                if proc.poll() is None:
                    proc.kill()


# =========================
# Pipeline
# =========================


class Pipeline:
    TOOL_NAMES = ["naabu", "dnsx", "httpx", "tlsx", "katana", "nuclei"]

    def __init__(self, cfg: PipelineConfig, run_dir: Path):
        self.cfg = cfg
        self.run_dir = run_dir
        self.log = self._setup_logging()
        self.db = StateDB(run_dir / "state.sqlite3")
        self.runner = CommandRunner(cfg.retries, cfg.retry_backoff_sec, self.log)

        self.db.set_meta("created_at", self.db.get_meta("created_at") or utc_now())
        self.db.set_meta("config_json", json.dumps(asdict(cfg), ensure_ascii=False))

        self.inputs_dir = ensure_dir(run_dir / "input")
        self.asns_root = ensure_dir(run_dir / "asns")
        self.aggregate_dir = ensure_dir(run_dir / "aggregate")
        self.report_dir = ensure_dir(run_dir / "report")
        self.logs_dir = ensure_dir(run_dir / "logs")

        self.history = HistoryDB(Path(self.cfg.history_db_path))
        self.interesting_title_re = re.compile(self.cfg.interesting_title_regex, re.I)
        self.interesting_tech_re = re.compile(self.cfg.interesting_tech_regex, re.I)

    def _setup_logging(self) -> logging.Logger:
        ensure_dir(self.run_dir / "logs")
        logger = logging.getLogger(f"pd_pipeline_{id(self)}")
        logger.setLevel(getattr(logging, self.cfg.log_level.upper(), logging.INFO))
        logger.handlers.clear()

        fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(fmt)
        logger.addHandler(sh)

        fh = logging.FileHandler(
            self.run_dir / "logs" / "pipeline.log", encoding="utf-8"
        )
        fh.setFormatter(fmt)
        logger.addHandler(fh)

        return logger

    def stage_bgp_inventory(self, asns: list[str]) -> None:
        stage = "bgp_inventory"
        outputs = [self.asn_dir(asn) / "inventory" / "cidrs.txt" for asn in asns]

        if self.stage_should_skip("_global", stage, outputs):
            self.log.info("[global] skip bgp_inventory")
            return

        stdout_file = self.aggregate_dir / "bgp_inventory.stdout.txt"
        stderr_file = self.logs_dir / "bgp_inventory.stderr.txt"
        self.db.begin_stage(
            "_global",
            stage,
            ["python", "bgp_inventory_lookup"],
            stdout_file,
            stderr_file,
        )

        try:
            db_path = Path(self.cfg.history_db_path).parent / "asn_prefixes.sqlite3"
            prefix_counts: dict[str, int] = {}

            for asn in asns:
                prefixes = lookup_prefixes_for_asn(db_path, asn)
                out_dir = ensure_dir(self.asn_dir(asn) / "inventory")
                write_lines(out_dir / "cidrs.txt", prefixes)
                prefix_counts[asn] = len(prefixes)

            metrics = {
                "asns": len(asns),
                "prefix_counts": prefix_counts,
                "db_path": str(db_path),
            }
            self.db.end_stage("_global", stage, "success", metrics=metrics)
        except Exception as e:
            self.db.end_stage("_global", stage, "failed", note=str(e))
            raise

    def _download_to_cache(self, url: str, dest: Path) -> Path:
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists() and dest.stat().st_size > 0:
            return dest

        req = Request(url, headers={"User-Agent": "pd-asn-pipeline/1.0"})
        with urlopen(req, timeout=300) as resp, dest.open("wb") as out:
            shutil.copyfileobj(resp, out)

        return dest

    def _resolve_bgp_source(self, source: dict[str, str]) -> Path:
        kind = source.get("kind", "path").strip().lower()
        value = source.get("value", "").strip()
        if not value:
            raise PipelineError("Invalid bgp_mrt_sources entry: missing value")

        if kind == "path":
            path = Path(value)
            if not path.exists():
                raise PipelineError(f"BGP MRT file not found: {path}")
            return path

        if kind == "url":
            cache_dir = ensure_dir(Path(self.cfg.bgp_cache_dir))
            parsed = urlparse(value)
            base_name = Path(parsed.path).name or f"mrt-{sha256_text(value)[:16]}.mrt"
            cached = cache_dir / f"{sha256_text(value)[:12]}-{base_name}"
            return self._download_to_cache(value, cached)

        raise PipelineError(f"Unsupported BGP MRT source kind: {kind}")

    def _origin_as_from_path_attributes(
        self, path_attributes: list[dict[str, Any]], bgp_attr_t: dict[str, int]
    ) -> str | None:
        as_path: list[str] = []
        as4_path: list[str] = []

        for attr in path_attributes or []:
            attr_type = enum_value(attr.get("type"))
            if attr_type == bgp_attr_t["AS_PATH"]:
                as_path = flatten_as_path_segments(attr.get("value", []))
            elif attr_type == bgp_attr_t["AS4_PATH"]:
                as4_path = flatten_as_path_segments(attr.get("value", []))

        merged = as4_path or as_path
        return merged[-1] if merged else None

    def _collect_prefixes_from_mrt(
        self, mrt_path: Path, target_asns: set[str]
    ) -> dict[str, set[str]]:
        from mrtparse import BGP_ATTR_T, MRT_T, TD_V2_ST, Reader

        results: dict[str, set[str]] = {asn: set() for asn in target_asns}

        for entry in Reader(str(mrt_path)):
            if getattr(entry, "err", None):
                continue

            m = entry.data
            mrt_type = enum_value(m.get("type"))

            if mrt_type == MRT_T["TABLE_DUMP"]:
                prefix = f"{m['prefix']}/{m['length']}"
                origin_as = self._origin_as_from_path_attributes(
                    m.get("path_attributes", []),
                    BGP_ATTR_T,
                )
                if origin_as in target_asns:
                    results[origin_as].add(prefix)

            elif mrt_type == MRT_T["TABLE_DUMP_V2"]:
                subtype = enum_value(m.get("subtype"))

                if subtype == TD_V2_ST["PEER_INDEX_TABLE"]:
                    continue

                if "prefix" not in m or "rib_entries" not in m:
                    continue

                prefix = f"{m['prefix']}/{m['length']}"

                for rib_entry in m.get("rib_entries", []):
                    origin_as = self._origin_as_from_path_attributes(
                        rib_entry.get("path_attributes", []),
                        BGP_ATTR_T,
                    )
                    if origin_as in target_asns:
                        results[origin_as].add(prefix)
                        break

        return results

    def close(self) -> None:
        self.db.close()
        self.history.close()

    def _tool_path(self, attr_name: str) -> str:
        return getattr(self.cfg, attr_name)

    def check_or_bootstrap_tools(self) -> None:
        missing: list[str] = []
        tool_bins = {
            "naabu": self.cfg.naabu_bin,
            "dnsx": self.cfg.dnsx_bin,
            "httpx": self.cfg.httpx_bin,
            "tlsx": self.cfg.tlsx_bin,
            "katana": self.cfg.katana_bin,
            "nuclei": self.cfg.nuclei_bin,
        }

        for logical, binary in tool_bins.items():
            if shutil.which(binary) is None:
                missing.append(logical)

        if (
            self.cfg.auto_install_missing_tools or self.cfg.auto_update_tools
        ) and shutil.which(self.cfg.pdtm_bin) is None:
            raise PipelineError(
                "pdtm is required for auto-install/auto-update but is not in PATH"
            )

        if self.cfg.auto_install_missing_tools and missing:
            self.log.info(
                "Installing missing ProjectDiscovery tools with PDTM: %s",
                ", ".join(missing),
            )
            cmd = [self.cfg.pdtm_bin, "-i", ",".join(missing)]
            self.runner.run(
                cmd,
                self.logs_dir / "pdtm_install.stdout.txt",
                self.logs_dir / "pdtm_install.stderr.txt",
                timeout_sec=7200,
            )

        if self.cfg.auto_update_tools:
            self.log.info("Updating ProjectDiscovery tools with PDTM")
            cmd = [self.cfg.pdtm_bin, "-ua"]
            self.runner.run(
                cmd,
                self.logs_dir / "pdtm_update.stdout.txt",
                self.logs_dir / "pdtm_update.stderr.txt",
                timeout_sec=7200,
            )

        still_missing = [
            logical
            for logical, binary in tool_bins.items()
            if shutil.which(binary) is None
        ]
        if still_missing:
            raise PipelineError(
                "Missing tools in PATH: "
                + ", ".join(still_missing)
                + ". Install them first (for example: pdtm -ia)."
            )

    def load_asns(self) -> list[str]:
        src = Path(self.cfg.asn_file).resolve()
        if not src.exists():
            raise PipelineError(f"ASN input file not found: {src}")
        asns = []
        for line in src.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            if not line.upper().startswith("AS"):
                line = f"AS{line}"
            asns.append(line.upper())
        asns = sorted(set(asns))
        if not asns:
            raise PipelineError("ASN input file is empty")
        shutil.copy2(src, self.inputs_dir / "asns.txt")
        return asns

    def asn_dir(self, asn: str) -> Path:
        return ensure_dir(self.asns_root / slug(asn))

    def stage_should_skip(self, asn: str, stage: str, outputs: list[Path]) -> bool:
        if self.cfg.force:
            return False
        state = self.db.get_stage(asn, stage)
        if not state or state["status"] != "success":
            return False
        return all(p.exists() for p in outputs)

    def run(self) -> None:
        self.check_or_bootstrap_tools()
        asns = self.load_asns()

        self.stage_bgp_inventory(asns)

        for asn in asns:
            self.log.info("=== %s ===", asn)
            self.stage_naabu(asn)
            self.stage_ptr(asn)
            self.stage_httpx(asn)
            self.stage_screenshots(asn)
            self.stage_tlsx(asn)
            self.stage_katana(asn)
            self.stage_nuclei(asn)

        self.stage_aggregate(asns)
        self.stage_history_diff(asns)
        self.stage_report(asns)

    # -------------------------
    # Individual stages
    # -------------------------

    def stage_naabu(self, asn: str) -> None:
        asn_root = self.asn_dir(asn)
        inventory_dir = asn_root / "inventory"
        cidrs_file = inventory_dir / "cidrs.txt"

        out_dir = ensure_dir(asn_root / "exposure" / "ports")
        jsonl_file = out_dir / "naabu.jsonl"
        ips_file = out_dir / "ips.txt"
        hostports_file = out_dir / "hostports.txt"
        outputs = [jsonl_file, ips_file, hostports_file]

        if self.stage_should_skip(asn, "naabu", outputs):
            self.log.info("[%s] skip naabu", asn)
            return

        stdout_file = jsonl_file
        stderr_file = self.logs_dir / f"{slug(asn)}.naabu.stderr.txt"
        cmd = [
            self.cfg.naabu_bin,
            "-json",
            "-top-ports",
            str(self.cfg.naabu_top_ports),
            "-rate",
            str(self.cfg.naabu_rate),
            "-scan-type",
            "s",
            "-exclude-cdn",
            "-list",
            str(cidrs_file),
        ]

        self.db.begin_stage(asn, "naabu", cmd, stdout_file, stderr_file)
        try:
            cidrs = read_lines(cidrs_file)
            if not cidrs:
                touch_empty(jsonl_file)
                touch_empty(ips_file)
                touch_empty(hostports_file)
                metrics = {
                    "open_port_records": 0,
                    "unique_ips": 0,
                    "unique_hostports": 0,
                    "note": "no CIDRs generated for this ASN",
                }
                self.db.end_stage(asn, "naabu", "success", metrics=metrics)
                return

            self.runner.run(
                cmd,
                stdout_file,
                stderr_file,
                timeout_sec=self.cfg.naabu_timeout_sec,
            )

            ips: list[str] = []
            hostports: list[str] = []

            for row in iter_jsonl(jsonl_file):
                ip = row.get("ip") or row.get("host")
                port = row.get("port")
                if ip:
                    ips.append(str(ip))
                if ip and port is not None:
                    hostports.append(f"{ip}:{port}")

            write_lines(ips_file, ips)
            write_lines(hostports_file, hostports)

            metrics = {
                "open_port_records": sum(1 for _ in iter_jsonl(jsonl_file)),
                "unique_ips": len(read_lines(ips_file)),
                "unique_hostports": len(read_lines(hostports_file)),
            }
            self.db.end_stage(asn, "naabu", "success", metrics=metrics)
        except Exception as e:
            self.db.end_stage(asn, "naabu", "failed", note=str(e))
            raise

    def stage_ptr(self, asn: str) -> None:
        asn_root = self.asn_dir(asn)
        ports_dir = asn_root / "exposure" / "ports"
        input_ips = ports_dir / "ips.txt"

        out_dir = ensure_dir(asn_root / "inventory")
        ptr_file = out_dir / "ptr_domains.txt"
        outputs = [ptr_file]

        if self.stage_should_skip(asn, "ptr", outputs):
            self.log.info("[%s] skip ptr", asn)
            return

        ips = read_lines(input_ips)
        stdout_file = ptr_file
        stderr_file = self.logs_dir / f"{slug(asn)}.dnsx.stderr.txt"
        cmd = [self.cfg.dnsx_bin, "-silent", "-ptr", "-resp-only", "-retry", "3"]

        self.db.begin_stage(asn, "ptr", cmd, stdout_file, stderr_file)
        try:
            if not ips:
                touch_empty(ptr_file)
            else:
                self.runner.run(
                    cmd,
                    stdout_file,
                    stderr_file,
                    stdin_text="\n".join(ips) + "\n",
                    timeout_sec=self.cfg.dnsx_timeout_sec,
                )
                write_lines(ptr_file, read_lines(ptr_file))
            metrics = {"ptr_domains": len(read_lines(ptr_file))}
            self.db.end_stage(asn, "ptr", "success", metrics=metrics)
        except Exception as e:
            self.db.end_stage(asn, "ptr", "failed", note=str(e))
            raise

    def stage_httpx(self, asn: str) -> None:
        asn_root = self.asn_dir(asn)
        ports_dir = asn_root / "exposure" / "ports"
        hostports_file = ports_dir / "hostports.txt"

        out_dir = ensure_dir(asn_root / "exposure" / "http")
        jsonl_file = out_dir / "httpx.jsonl"
        live_urls_file = out_dir / "live_urls.txt"
        outputs = [jsonl_file, live_urls_file]

        if self.stage_should_skip(asn, "httpx", outputs):
            self.log.info("[%s] skip httpx", asn)
            return

        response_dir = ensure_dir(out_dir / "responses")
        stdout_file = jsonl_file
        stderr_file = self.logs_dir / f"{slug(asn)}.httpx.stderr.txt"

        cmd = [
            self.cfg.httpx_bin,
            "-j",
            "-sc",
            "-title",
            "-server",
            "-td",
            "-jarm",
            "-tls-grab",
            "-favicon",
            "-asn",
            "-extract-fqdn",
            "-ob",
            "-t",
            str(self.cfg.httpx_threads),
            "-rl",
            str(self.cfg.httpx_rate_limit),
        ]
        if self.cfg.httpx_store_responses:
            cmd += ["-sr", "-srd", str(response_dir)]

        self.db.begin_stage(asn, "httpx", cmd, stdout_file, stderr_file)
        try:
            hostports = read_lines(hostports_file)
            if not hostports:
                touch_empty(jsonl_file)
                touch_empty(live_urls_file)
                metrics = {"live_urls": 0}
                self.db.end_stage(asn, "httpx", "success", metrics=metrics)
                return

            self.runner.run(
                cmd,
                stdout_file,
                stderr_file,
                stdin_text="\n".join(hostports) + "\n",
                timeout_sec=self.cfg.httpx_timeout_sec,
            )

            urls = []
            for row in iter_jsonl(jsonl_file):
                u = get_httpx_url(row)
                if u:
                    urls.append(u)

            write_lines(live_urls_file, urls)
            metrics = {
                "live_urls": len(read_lines(live_urls_file)),
                "httpx_records": sum(1 for _ in iter_jsonl(jsonl_file)),
            }
            self.db.end_stage(asn, "httpx", "success", metrics=metrics)
        except Exception as e:
            self.db.end_stage(asn, "httpx", "failed", note=str(e))
            raise

    def stage_screenshots(self, asn: str) -> None:
        asn_root = self.asn_dir(asn)
        http_dir = asn_root / "exposure" / "http"
        live_urls_file = http_dir / "live_urls.txt"

        out_dir = ensure_dir(http_dir / "screenshots")
        jsonl_file = http_dir / "httpx_screenshots.jsonl"
        outputs = [jsonl_file, out_dir]

        if self.stage_should_skip(asn, "screenshots", outputs):
            self.log.info("[%s] skip screenshots", asn)
            return

        stdout_file = jsonl_file
        stderr_file = self.logs_dir / f"{slug(asn)}.httpx_screenshots.stderr.txt"
        cmd = [
            self.cfg.httpx_bin,
            "-j",
            "-ss",
            "-esb",
            "-ehb",
            "-srd",
            str(out_dir),
            "-st",
            str(self.cfg.httpx_screenshot_timeout_seconds),
        ]
        if self.cfg.httpx_system_chrome:
            cmd.append("-system-chrome")

        self.db.begin_stage(asn, "screenshots", cmd, stdout_file, stderr_file)
        try:
            urls = read_lines(live_urls_file)[: self.cfg.httpx_screenshot_limit_per_asn]
            if not urls:
                touch_empty(jsonl_file)
                self.db.end_stage(
                    asn, "screenshots", "success", metrics={"screenshots_targets": 0}
                )
                return

            self.runner.run(
                cmd,
                stdout_file,
                stderr_file,
                stdin_text="\n".join(urls) + "\n",
                timeout_sec=self.cfg.screenshots_timeout_sec,
            )

            metrics = {
                "screenshots_targets": len(urls),
                "screenshot_files": sum(1 for p in out_dir.rglob("*") if p.is_file()),
            }
            self.db.end_stage(asn, "screenshots", "success", metrics=metrics)
        except Exception as e:
            self.db.end_stage(asn, "screenshots", "failed", note=str(e))
            raise

    def stage_tlsx(self, asn: str) -> None:
        asn_root = self.asn_dir(asn)
        http_dir = asn_root / "exposure" / "http"
        live_urls_file = http_dir / "live_urls.txt"

        out_dir = ensure_dir(asn_root / "exposure" / "tls")
        jsonl_file = out_dir / "tlsx.jsonl"
        dns_names_file = out_dir / "tls_dns_names.txt"
        outputs = [jsonl_file, dns_names_file]

        if self.stage_should_skip(asn, "tlsx", outputs):
            self.log.info("[%s] skip tlsx", asn)
            return

        stdout_file = jsonl_file
        stderr_file = self.logs_dir / f"{slug(asn)}.tlsx.stderr.txt"
        cmd = [self.cfg.tlsx_bin, "-j", "-silent"]

        self.db.begin_stage(asn, "tlsx", cmd, stdout_file, stderr_file)
        try:
            https_targets = []
            for url in read_lines(live_urls_file):
                if url.startswith("https://"):
                    hp = parse_url_hostport(url)
                    if hp:
                        https_targets.append(hp)

            if not https_targets:
                touch_empty(jsonl_file)
                touch_empty(dns_names_file)
                self.db.end_stage(
                    asn, "tlsx", "success", metrics={"tls_records": 0, "dns_names": 0}
                )
                return

            write_lines(out_dir / "https_targets.txt", https_targets)

            self.runner.run(
                cmd,
                stdout_file,
                stderr_file,
                stdin_text="\n".join(sorted(set(https_targets))) + "\n",
                timeout_sec=self.cfg.tlsx_timeout_sec,
            )

            dns_names = []
            for row in iter_jsonl(jsonl_file):
                cn = row.get("subject_cn")
                if isinstance(cn, str) and cn.strip():
                    dns_names.append(cn.strip())
                sans = row.get("subject_an")
                if isinstance(sans, list):
                    dns_names.extend(str(x).strip() for x in sans if str(x).strip())

            write_lines(dns_names_file, dns_names)
            metrics = {
                "tls_records": sum(1 for _ in iter_jsonl(jsonl_file)),
                "dns_names": len(read_lines(dns_names_file)),
            }
            self.db.end_stage(asn, "tlsx", "success", metrics=metrics)
        except Exception as e:
            self.db.end_stage(asn, "tlsx", "failed", note=str(e))
            raise

    def stage_katana(self, asn: str) -> None:
        if not self.cfg.katana_enabled:
            self.db.end_stage(
                asn, "katana", "success", note="disabled", metrics={"enabled": False}
            )
            return

        asn_root = self.asn_dir(asn)
        http_dir = asn_root / "exposure" / "http"
        live_urls_file = http_dir / "live_urls.txt"

        out_dir = ensure_dir(asn_root / "content")
        jsonl_file = out_dir / "katana.jsonl"
        outputs = [jsonl_file]

        if self.stage_should_skip(asn, "katana", outputs):
            self.log.info("[%s] skip katana", asn)
            return

        stdout_file = jsonl_file
        stderr_file = self.logs_dir / f"{slug(asn)}.katana.stderr.txt"
        cmd = [
            self.cfg.katana_bin,
            "-list",
            str(live_urls_file),
            "-d",
            str(self.cfg.katana_depth),
            "-kf",
            self.cfg.katana_known_files,
            "-ct",
            self.cfg.katana_crawl_duration,
            "-mrs",
            str(self.cfg.katana_max_response_size),
            "-timeout",
            str(self.cfg.katana_request_timeout_seconds),
            "-retry",
            str(self.cfg.katana_retry),
            "-iqp",
            "-j",
            "-or",
            "-ob",
        ]

        self.db.begin_stage(asn, "katana", cmd, stdout_file, stderr_file)
        try:
            if not read_lines(live_urls_file):
                touch_empty(jsonl_file)
                self.db.end_stage(
                    asn, "katana", "success", metrics={"katana_records": 0}
                )
                return

            self.runner.run(
                cmd,
                stdout_file,
                stderr_file,
                timeout_sec=self.cfg.katana_timeout_sec,
            )
            metrics = {"katana_records": sum(1 for _ in iter_jsonl(jsonl_file))}
            self.db.end_stage(asn, "katana", "success", metrics=metrics)
        except Exception as e:
            self.db.end_stage(asn, "katana", "failed", note=str(e))
            raise

    def stage_nuclei(self, asn: str) -> None:
        if not self.cfg.nuclei_enabled:
            self.db.end_stage(
                asn, "nuclei", "success", note="disabled", metrics={"enabled": False}
            )
            return

        asn_root = self.asn_dir(asn)
        http_dir = asn_root / "exposure" / "http"
        live_urls_file = http_dir / "live_urls.txt"

        out_dir = ensure_dir(asn_root / "findings")
        markdown_dir = ensure_dir(out_dir / "markdown")
        reportdb_dir = ensure_dir(out_dir / "reportdb")
        project_dir = ensure_dir(out_dir / "project")
        json_file = out_dir / "nuclei.json"
        jsonl_file = out_dir / "nuclei.jsonl"
        outputs = [json_file, jsonl_file, markdown_dir, reportdb_dir]

        if self.stage_should_skip(asn, "nuclei", outputs):
            self.log.info("[%s] skip nuclei", asn)
            return

        stdout_file = out_dir / "nuclei.stdout.txt"
        stderr_file = self.logs_dir / f"{slug(asn)}.nuclei.stderr.txt"
        cmd = [
            self.cfg.nuclei_bin,
            "-l",
            str(live_urls_file),
            "-severity",
            ",".join(self.cfg.nuclei_severity),
            "-rl",
            str(self.cfg.nuclei_rate_limit),
            "-bs",
            str(self.cfg.nuclei_bulk_size),
            "-c",
            str(self.cfg.nuclei_concurrency),
            "-timeout",
            str(self.cfg.nuclei_request_timeout_seconds),
            "-retries",
            str(self.cfg.nuclei_request_retries),
            "-rdb",
            str(reportdb_dir),
            "-me",
            str(markdown_dir),
            "-je",
            str(json_file),
            "-jle",
            str(jsonl_file),
            "-project",
            "-project-path",
            str(project_dir),
            "-or",
        ]

        if self.cfg.nuclei_exclude_tags:
            cmd += ["-etags", ",".join(self.cfg.nuclei_exclude_tags)]
        for key in self.cfg.nuclei_redact_keys:
            cmd += ["-rd", key]
        if self.cfg.nuclei_include_request_response:
            cmd.append("-irr")
        cmd += self.cfg.nuclei_extra_args

        self.db.begin_stage(asn, "nuclei", cmd, stdout_file, stderr_file)
        try:
            if not read_lines(live_urls_file):
                touch_empty(stdout_file)
                touch_empty(json_file)
                touch_empty(jsonl_file)
                self.db.end_stage(asn, "nuclei", "success", metrics={"findings": 0})
                return

            self.runner.run(
                cmd,
                stdout_file,
                stderr_file,
                timeout_sec=self.cfg.nuclei_timeout_sec,
            )
            findings = sum(1 for _ in iter_jsonl(jsonl_file))
            self.db.end_stage(asn, "nuclei", "success", metrics={"findings": findings})
        except Exception as e:
            self.db.end_stage(asn, "nuclei", "failed", note=str(e))
            raise

    def _asset_locator(self, asset: dict[str, Any]) -> str:
        return (
            asset.get("url")
            or asset.get("service")
            or asset.get("canonical")
            or asset.get("asset_key", "")
        )

    def _score_asset_interest(self, asset: dict[str, Any]) -> tuple[int, str]:
        score = 0
        reasons: list[str] = []

        port = asset.get("port")
        title = str(asset.get("title") or "")
        tech_text = " ".join(asset.get("tech") or [])

        if isinstance(port, int) and port in set(self.cfg.interesting_ports):
            score += 15
            reasons.append(f"sensitive-port:{port}")

        if title and self.interesting_title_re.search(title):
            score += 20
            reasons.append("interesting-title")

        if tech_text and self.interesting_tech_re.search(tech_text):
            score += 20
            reasons.append("interesting-tech")

        return score, ", ".join(reasons)

    def _build_asset_snapshots(self) -> dict[str, dict[str, Any]]:
        assets: dict[str, dict[str, Any]] = {}

        # Service-level assets from Naabu
        for row in iter_jsonl(self.aggregate_dir / "naabu.jsonl"):
            ip = str(row.get("ip") or row.get("host") or "").strip()
            port = row.get("port")
            if not ip or port is None:
                continue

            try:
                port_int = int(port)
            except Exception:
                continue

            asset = {
                "asset_key": f"service|{ip}:{port_int}",
                "asset_type": "service",
                "asn": str(row.get("_asn", "")),
                "service": f"{ip}:{port_int}",
                "url": "",
                "canonical": f"{ip}:{port_int}",
                "ip": ip,
                "port": port_int,
                "status": None,
                "title": "",
                "server": "",
                "tech": [],
                "cdn": "",
            }
            interest_score, interest_reason = self._score_asset_interest(asset)
            asset["interest_score"] = interest_score
            asset["interest_reason"] = interest_reason
            asset["fingerprint"] = stable_json_hash(
                {
                    "service": asset["service"],
                    "port": asset["port"],
                }
            )
            assets[asset["asset_key"]] = asset

        # Web assets from httpx
        for row in iter_jsonl(self.aggregate_dir / "httpx.jsonl"):
            url = get_httpx_url(row)
            if not url:
                continue

            canonical = canonical_url(url)
            hostport = parse_url_hostport(canonical) or ""
            port_int: int | None = None
            if ":" in hostport:
                maybe_port = hostport.rsplit(":", 1)[-1]
                if maybe_port.isdigit():
                    port_int = int(maybe_port)

            tech = sorted(set(get_httpx_tech(row)))
            asset = {
                "asset_key": f"web|{canonical}",
                "asset_type": "web",
                "asn": str(row.get("_asn", "")),
                "service": hostport,
                "url": canonical,
                "canonical": canonical,
                "ip": "",
                "port": port_int,
                "status": get_httpx_status(row),
                "title": get_httpx_title(row),
                "server": get_httpx_server(row),
                "tech": tech,
                "cdn": get_httpx_cdn(row),
            }
            interest_score, interest_reason = self._score_asset_interest(asset)
            asset["interest_score"] = interest_score
            asset["interest_reason"] = interest_reason
            asset["fingerprint"] = stable_json_hash(
                {
                    "url": asset["url"],
                    "status": asset["status"],
                    "title": asset["title"],
                    "server": asset["server"],
                    "tech": asset["tech"],
                    "cdn": asset["cdn"],
                }
            )
            assets[asset["asset_key"]] = asset

        return assets

    def _build_finding_snapshots(self) -> dict[str, dict[str, Any]]:
        findings: dict[str, dict[str, Any]] = {}

        for row in iter_jsonl(self.aggregate_dir / "nuclei.jsonl"):
            info = row.get("info") or {}
            template_id = str(row.get("template-id") or "")
            if not template_id:
                continue

            severity = str(info.get("severity", "unknown")).lower()
            sev_weight = severity_weight(severity)
            target = str(
                row.get("matched-at") or row.get("host") or row.get("url") or ""
            ).strip()
            canonical = canonical_target(target)
            finding_key = sha256_text(f"{template_id}|{canonical}")

            finding = {
                "finding_key": finding_key,
                "asn": str(row.get("_asn", "")),
                "template_id": template_id,
                "name": str(info.get("name") or template_id),
                "severity": severity,
                "severity_weight": sev_weight,
                "target": target,
                "canonical_target": canonical,
                "matcher_name": str(row.get("matcher-name") or ""),
            }
            finding["fingerprint"] = stable_json_hash(
                {
                    "template_id": finding["template_id"],
                    "canonical_target": finding["canonical_target"],
                    "severity": finding["severity"],
                }
            )
            findings[finding_key] = finding

        return findings

    def _sort_assets(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return sorted(
            rows,
            key=lambda x: (
                -int(x.get("interest_score", 0)),
                x.get("asset_type", ""),
                x.get("asn", ""),
                self._asset_locator(x),
            ),
        )

    def _sort_findings(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return sorted(
            rows,
            key=lambda x: (
                -int(x.get("severity_weight", 0)),
                x.get("asn", ""),
                x.get("name", ""),
                x.get("target", ""),
            ),
        )

    def stage_history_diff(self, asns: list[str]) -> None:
        stage = "history_diff"
        diff_file = self.aggregate_dir / "diff.json"
        outputs = [diff_file]

        if self.stage_should_skip("_global", stage, outputs):
            self.log.info("[global] skip history_diff")
            return

        stdout_file = self.aggregate_dir / "history_diff.stdout.txt"
        stderr_file = self.logs_dir / "history_diff.stderr.txt"
        self.db.begin_stage(
            "_global", stage, ["python", "history_diff"], stdout_file, stderr_file
        )

        try:
            run_id = self.run_dir.name
            started_at = self.db.get_meta("created_at") or utc_now()
            finished_at = utc_now()

            self.history.ensure_run(run_id, started_at, str(self.run_dir))
            previous_run_id = self.history.previous_run(run_id, started_at)

            known_asset_keys_before = self.history.seen_asset_keys_before(started_at)
            known_finding_keys_before = self.history.seen_finding_keys_before(
                started_at
            )

            previous_assets = self.history.asset_records_for_run(previous_run_id)
            previous_findings = self.history.finding_records_for_run(previous_run_id)

            current_assets = self._build_asset_snapshots()
            current_findings = self._build_finding_snapshots()

            current_asset_keys = set(current_assets.keys())
            previous_asset_keys = set(previous_assets.keys())

            current_finding_keys = set(current_findings.keys())
            previous_finding_keys = set(previous_findings.keys())

            new_assets = [
                current_assets[k]
                for k in (current_asset_keys - known_asset_keys_before)
            ]
            resurfaced_assets = [
                current_assets[k]
                for k in (
                    (current_asset_keys & known_asset_keys_before) - previous_asset_keys
                )
            ]
            resolved_assets = [
                previous_assets[k] for k in (previous_asset_keys - current_asset_keys)
            ]

            changed_web_assets: list[dict[str, Any]] = []
            for asset_key in current_asset_keys & previous_asset_keys:
                current = current_assets[asset_key]
                previous = previous_assets[asset_key]
                if current.get("asset_type") != "web":
                    continue
                if current.get("fingerprint") == previous.get("fingerprint"):
                    continue

                changes: dict[str, dict[str, Any]] = {}
                for field_name in ("status", "title", "server", "tech", "cdn"):
                    if current.get(field_name) != previous.get(field_name):
                        changes[field_name] = {
                            "before": previous.get(field_name),
                            "after": current.get(field_name),
                        }

                if changes:
                    changed_web_assets.append(
                        {
                            **current,
                            "changes": changes,
                        }
                    )

            new_interesting_assets = []
            for asset_key, asset in current_assets.items():
                if int(asset.get("interest_score", 0)) <= 0:
                    continue
                previous_interest = int(
                    previous_assets.get(asset_key, {}).get("interest_score", 0)
                )
                if asset_key not in known_asset_keys_before or previous_interest <= 0:
                    new_interesting_assets.append(asset)

            new_findings = [
                current_findings[k]
                for k in (current_finding_keys - known_finding_keys_before)
            ]
            resurfaced_findings = [
                current_findings[k]
                for k in (
                    (current_finding_keys & known_finding_keys_before)
                    - previous_finding_keys
                )
            ]
            resolved_findings = [
                previous_findings[k]
                for k in (previous_finding_keys - current_finding_keys)
            ]

            worsened_findings: list[dict[str, Any]] = []
            for finding_key in current_finding_keys & previous_finding_keys:
                current = current_findings[finding_key]
                previous = previous_findings[finding_key]
                if int(current.get("severity_weight", 0)) > int(
                    previous.get("severity_weight", 0)
                ):
                    worsened_findings.append(
                        {
                            **current,
                            "previous_severity": previous.get("severity", "unknown"),
                        }
                    )

            new_high_signal_findings = [
                f
                for f in (new_findings + resurfaced_findings)
                if int(f.get("severity_weight", 0)) >= severity_weight("high")
            ]

            new_assets = self._sort_assets(new_assets)[: self.cfg.diff_max_items]
            resurfaced_assets = self._sort_assets(resurfaced_assets)[
                : self.cfg.diff_max_items
            ]
            resolved_assets = self._sort_assets(resolved_assets)[
                : self.cfg.diff_max_items
            ]
            changed_web_assets = self._sort_assets(changed_web_assets)[
                : self.cfg.diff_max_items
            ]
            new_interesting_assets = self._sort_assets(new_interesting_assets)[
                : self.cfg.diff_max_items
            ]

            new_findings = self._sort_findings(new_findings)[: self.cfg.diff_max_items]
            resurfaced_findings = self._sort_findings(resurfaced_findings)[
                : self.cfg.diff_max_items
            ]
            resolved_findings = self._sort_findings(resolved_findings)[
                : self.cfg.diff_max_items
            ]
            worsened_findings = self._sort_findings(worsened_findings)[
                : self.cfg.diff_max_items
            ]
            new_high_signal_findings = self._sort_findings(new_high_signal_findings)[
                : self.cfg.diff_max_items
            ]

            diff_payload = {
                "run_id": run_id,
                "previous_run_id": previous_run_id,
                "generated_at": finished_at,
                "counts": {
                    "new_assets": len(new_assets),
                    "resurfaced_assets": len(resurfaced_assets),
                    "resolved_assets": len(resolved_assets),
                    "changed_web_assets": len(changed_web_assets),
                    "new_interesting_assets": len(new_interesting_assets),
                    "new_findings": len(new_findings),
                    "resurfaced_findings": len(resurfaced_findings),
                    "resolved_findings": len(resolved_findings),
                    "worsened_findings": len(worsened_findings),
                    "new_high_signal_findings": len(new_high_signal_findings),
                },
                "new_assets": new_assets,
                "resurfaced_assets": resurfaced_assets,
                "resolved_assets": resolved_assets,
                "changed_web_assets": changed_web_assets,
                "new_interesting_assets": new_interesting_assets,
                "new_findings": new_findings,
                "resurfaced_findings": resurfaced_findings,
                "resolved_findings": resolved_findings,
                "worsened_findings": worsened_findings,
                "new_high_signal_findings": new_high_signal_findings,
            }

            json_dump_file(diff_file, diff_payload)

            # Only after diffing, persist the current run into long-term history
            self.history.upsert_assets(
                run_id, list(current_assets.values()), finished_at
            )
            self.history.upsert_findings(
                run_id, list(current_findings.values()), finished_at
            )
            self.history.finish_run(run_id, finished_at)

            self.db.end_stage(
                "_global", stage, "success", metrics=diff_payload["counts"]
            )
        except Exception as e:
            self.db.end_stage("_global", stage, "failed", note=str(e))
            raise

    # -------------------------
    # Aggregate and report
    # -------------------------

    def stage_aggregate(self, asns: list[str]) -> None:
        stage = "aggregate"
        outputs = [
            self.aggregate_dir / "naabu.jsonl",
            self.aggregate_dir / "httpx.jsonl",
            self.aggregate_dir / "live_urls.txt",
            self.aggregate_dir / "tlsx.jsonl",
            self.aggregate_dir / "katana.jsonl",
            self.aggregate_dir / "nuclei.jsonl",
            self.aggregate_dir / "summary.json",
        ]
        if self.stage_should_skip("_global", stage, outputs):
            self.log.info("[global] skip aggregate")
            return

        stdout_file = self.aggregate_dir / "aggregate.stdout.txt"
        stderr_file = self.logs_dir / "aggregate.stderr.txt"
        self.db.begin_stage(
            "_global", stage, ["python", "aggregate"], stdout_file, stderr_file
        )

        try:
            naabu_out = self.aggregate_dir / "naabu.jsonl"
            httpx_out = self.aggregate_dir / "httpx.jsonl"
            live_urls_out = self.aggregate_dir / "live_urls.txt"
            tlsx_out = self.aggregate_dir / "tlsx.jsonl"
            katana_out = self.aggregate_dir / "katana.jsonl"
            nuclei_out = self.aggregate_dir / "nuclei.jsonl"

            for p in (naabu_out, httpx_out, tlsx_out, katana_out, nuclei_out):
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("", encoding="utf-8")

            all_live_urls: list[str] = []
            summary_per_asn: dict[str, dict[str, Any]] = {}

            with (
                naabu_out.open("w", encoding="utf-8") as f_naabu,
                httpx_out.open("w", encoding="utf-8") as f_httpx,
                tlsx_out.open("w", encoding="utf-8") as f_tlsx,
                katana_out.open("w", encoding="utf-8") as f_katana,
                nuclei_out.open("w", encoding="utf-8") as f_nuclei,
            ):
                for asn in asns:
                    asn_root = self.asn_dir(asn)

                    naabu_rows = list(
                        iter_jsonl(asn_root / "exposure" / "ports" / "naabu.jsonl")
                    )
                    httpx_rows = list(
                        iter_jsonl(asn_root / "exposure" / "http" / "httpx.jsonl")
                    )
                    tlsx_rows = list(
                        iter_jsonl(asn_root / "exposure" / "tls" / "tlsx.jsonl")
                    )
                    katana_rows = list(
                        iter_jsonl(asn_root / "content" / "katana.jsonl")
                    )
                    nuclei_rows = list(
                        iter_jsonl(asn_root / "findings" / "nuclei.jsonl")
                    )
                    live_urls = read_lines(
                        asn_root / "exposure" / "http" / "live_urls.txt"
                    )

                    summary_per_asn[asn] = {
                        "cidrs": len(read_lines(asn_root / "inventory" / "cidrs.txt")),
                        "ptr_domains": len(
                            read_lines(asn_root / "inventory" / "ptr_domains.txt")
                        ),
                        "open_port_records": len(naabu_rows),
                        "live_urls": len(live_urls),
                        "tls_records": len(tlsx_rows),
                        "katana_records": len(katana_rows),
                        "nuclei_findings": len(nuclei_rows),
                    }

                    for row in naabu_rows:
                        row["_asn"] = asn
                        f_naabu.write(json.dumps(row, ensure_ascii=False) + "\n")
                    for row in httpx_rows:
                        row["_asn"] = asn
                        f_httpx.write(json.dumps(row, ensure_ascii=False) + "\n")
                    for row in tlsx_rows:
                        row["_asn"] = asn
                        f_tlsx.write(json.dumps(row, ensure_ascii=False) + "\n")
                    for row in katana_rows:
                        row["_asn"] = asn
                        f_katana.write(json.dumps(row, ensure_ascii=False) + "\n")
                    for row in nuclei_rows:
                        row["_asn"] = asn
                        f_nuclei.write(json.dumps(row, ensure_ascii=False) + "\n")

                    all_live_urls.extend(live_urls)

            write_lines(live_urls_out, all_live_urls)

            summary = self._build_summary(asns, summary_per_asn)
            json_dump_file(self.aggregate_dir / "summary.json", summary)

            self.db.end_stage(
                "_global",
                stage,
                "success",
                metrics={
                    "asns": len(asns),
                    "live_urls": len(read_lines(live_urls_out)),
                },
            )
        except Exception as e:
            self.db.end_stage("_global", stage, "failed", note=str(e))
            raise

    def _build_summary(
        self, asns: list[str], summary_per_asn: dict[str, dict[str, Any]]
    ) -> dict[str, Any]:
        naabu_rows = load_jsonl(self.aggregate_dir / "naabu.jsonl")
        httpx_rows = load_jsonl(self.aggregate_dir / "httpx.jsonl")
        tlsx_rows = load_jsonl(self.aggregate_dir / "tlsx.jsonl")
        katana_rows = load_jsonl(self.aggregate_dir / "katana.jsonl")
        nuclei_rows = load_jsonl(self.aggregate_dir / "nuclei.jsonl")

        ports = Counter()
        for row in naabu_rows:
            port = row.get("port")
            if port is not None:
                ports[str(port)] += 1

        techs = Counter()
        servers = Counter()
        titles = Counter()
        interesting_assets = []
        mgmt_port_hits = []

        keyword_re = re.compile(
            r"(admin|login|jenkins|grafana|kibana|prometheus|vpn|dashboard|gitlab|jira|confluence|harbor|argocd|kubernetes|rabbitmq|sonarqube)",
            re.I,
        )
        sensitive_ports = {
            "21",
            "22",
            "23",
            "25",
            "53",
            "110",
            "143",
            "445",
            "465",
            "587",
            "993",
            "995",
            "1433",
            "1521",
            "2375",
            "2376",
            "3000",
            "3306",
            "3389",
            "5000",
            "5432",
            "5601",
            "5900",
            "6379",
            "6443",
            "8080",
            "8443",
            "9000",
            "9200",
            "9300",
            "11211",
            "27017",
        }

        for row in httpx_rows:
            url = get_httpx_url(row) or ""
            title = get_httpx_title(row)
            server = get_httpx_server(row)
            asn = row.get("_asn", "")
            if title:
                titles[title] += 1
            if server:
                servers[server] += 1
            for tech in get_httpx_tech(row):
                techs[tech] += 1

            hp = parse_url_hostport(url) if url else None
            if hp and hp.split(":")[-1] in sensitive_ports:
                mgmt_port_hits.append(
                    {"asn": asn, "url": url, "port": hp.split(":")[-1], "title": title}
                )

            if keyword_re.search(title) or any(
                keyword_re.search(t) for t in get_httpx_tech(row)
            ):
                interesting_assets.append(
                    {
                        "asn": asn,
                        "url": url,
                        "status": get_httpx_status(row),
                        "title": title,
                        "server": server,
                        "tech": get_httpx_tech(row),
                        "cdn": get_httpx_cdn(row),
                    }
                )

        severity_counts = Counter()
        top_findings = []

        for row in nuclei_rows:
            info = row.get("info") or {}
            sev = str(info.get("severity", "unknown")).lower()
            severity_counts[sev] += 1
            top_findings.append(
                {
                    "asn": row.get("_asn", ""),
                    "severity": sev,
                    "weight": severity_weight(sev),
                    "name": info.get("name") or row.get("template-id") or "unknown",
                    "template_id": row.get("template-id") or "",
                    "target": row.get("matched-at")
                    or row.get("host")
                    or row.get("url")
                    or "",
                }
            )

        top_findings.sort(key=lambda x: (-x["weight"], x["name"], x["target"]))

        tls_issuers = Counter()
        cert_subjects = []
        for row in tlsx_rows:
            issuer = row.get("issuer_cn")
            if issuer:
                tls_issuers[str(issuer)] += 1
            cert_subjects.append(
                {
                    "asn": row.get("_asn", ""),
                    "host": f"{row.get('host', '')}:{row.get('port', '')}",
                    "subject_cn": row.get("subject_cn", ""),
                    "issuer_cn": row.get("issuer_cn", ""),
                    "not_after": row.get("not_after", ""),
                }
            )

        return {
            "generated_at": utc_now(),
            "run_dir": str(self.run_dir),
            "counts": {
                "asns": len(asns),
                "open_port_records": len(naabu_rows),
                "httpx_records": len(httpx_rows),
                "live_urls": len(read_lines(self.aggregate_dir / "live_urls.txt")),
                "tls_records": len(tlsx_rows),
                "katana_records": len(katana_rows),
                "nuclei_findings": len(nuclei_rows),
            },
            "severity_counts": dict(severity_counts),
            "top_ports": ports.most_common(25),
            "top_techs": techs.most_common(25),
            "top_servers": servers.most_common(25),
            "top_titles": titles.most_common(25),
            "top_findings": top_findings[:200],
            "interesting_assets": interesting_assets[:200],
            "management_port_hits": mgmt_port_hits[:200],
            "tls_issuers": tls_issuers.most_common(25),
            "cert_subjects": cert_subjects[:200],
            "per_asn": summary_per_asn,
        }

    def stage_report(self, asns: list[str]) -> None:
        stage = "report"
        outputs = [self.report_dir / "index.html", self.report_dir / "raw.html"]

        if self.stage_should_skip("_global", stage, outputs):
            self.log.info("[global] skip report")
            return

        stdout_file = self.report_dir / "report.stdout.txt"
        stderr_file = self.logs_dir / "report.stderr.txt"
        self.db.begin_stage(
            "_global", stage, ["python", "render_report"], stdout_file, stderr_file
        )

        try:
            summary = json_load_file(self.aggregate_dir / "summary.json", {})
            diff_data = json_load_file(self.aggregate_dir / "diff.json", {})
            self._write_raw_browser()
            self._write_main_report(summary, asns, diff_data)
            self.db.end_stage("_global", stage, "success", metrics={"report_files": 2})
        except Exception as e:
            self.db.end_stage("_global", stage, "failed", note=str(e))
            raise

    def _write_raw_browser(self) -> None:
        rows = []
        for p in sorted(self.run_dir.rglob("*")):
            if not p.is_file():
                continue
            rel = p.relative_to(self.run_dir)
            if rel.as_posix().startswith("report/"):
                continue
            rows.append(
                "<tr>"
                f"<td><a href='../{html.escape(str(rel))}'>{html.escape(str(rel))}</a></td>"
                f"<td>{sizeof_fmt(p.stat().st_size)}</td>"
                "</tr>"
            )

        body = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Raw Results Browser</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 24px; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
th {{ background: #f5f5f5; }}
a {{ text-decoration: none; }}
</style>
</head>
<body>
<h1>Raw Results Browser</h1>
<p><a href="index.html">Back to main report</a></p>
<table>
<thead><tr><th>File</th><th>Size</th></tr></thead>
<tbody>
{"".join(rows)}
</tbody>
</table>
</body>
</html>"""
        write_text(self.report_dir / "raw.html", body)

    def _write_main_report(
        self, summary: dict[str, Any], asns: list[str], diff_data: dict[str, Any]
    ) -> None:
        counts = summary.get("counts", {})
        per_asn = summary.get("per_asn", {})
        sev = summary.get("severity_counts", {})
        diff_counts = diff_data.get("counts", {})
        previous_run_id = diff_data.get("previous_run_id")

        finding_rows = []
        for row in summary.get("top_findings", [])[:100]:
            finding_rows.append(
                "<tr>"
                f"<td>{html.escape(row.get('asn', ''))}</td>"
                f"<td>{html.escape(row.get('severity', ''))}</td>"
                f"<td>{html.escape(row.get('name', ''))}</td>"
                f"<td>{html.escape(row.get('template_id', ''))}</td>"
                f"<td>{html.escape(row.get('target', ''))}</td>"
                "</tr>"
            )

        interesting_rows = []
        for row in summary.get("interesting_assets", [])[:100]:
            interesting_rows.append(
                "<tr>"
                f"<td>{html.escape(row.get('asn', ''))}</td>"
                f"<td><a href='{html.escape(row.get('url', ''))}'>{html.escape(row.get('url', ''))}</a></td>"
                f"<td>{html.escape(str(row.get('status') or ''))}</td>"
                f"<td>{html.escape(row.get('title', ''))}</td>"
                f"<td>{html.escape(', '.join(row.get('tech') or []))}</td>"
                "</tr>"
            )

        asn_rows = []
        for asn in asns:
            r = per_asn.get(asn, {})
            asn_rows.append(
                "<tr>"
                f"<td><a href='../asns/{html.escape(slug(asn))}/'>{html.escape(asn)}</a></td>"
                f"<td>{r.get('cidrs', 0)}</td>"
                f"<td>{r.get('ptr_domains', 0)}</td>"
                f"<td>{r.get('open_port_records', 0)}</td>"
                f"<td>{r.get('live_urls', 0)}</td>"
                f"<td>{r.get('tls_records', 0)}</td>"
                f"<td>{r.get('katana_records', 0)}</td>"
                f"<td>{r.get('nuclei_findings', 0)}</td>"
                "</tr>"
            )

        def render_asset_table(rows: list[dict[str, Any]], title: str) -> str:
            body = []
            for row in rows[:100]:
                locator = (
                    row.get("url") or row.get("service") or row.get("canonical") or ""
                )
                body.append(
                    "<tr>"
                    f"<td>{html.escape(row.get('asset_type', ''))}</td>"
                    f"<td>{html.escape(row.get('asn', ''))}</td>"
                    f"<td>{html.escape(locator)}</td>"
                    f"<td>{html.escape(row.get('interest_reason', ''))}</td>"
                    "</tr>"
                )
            return (
                f"<h2>{html.escape(title)}</h2>"
                "<table>"
                "<thead><tr><th>Type</th><th>ASN</th><th>Asset</th><th>Reason</th></tr></thead>"
                f"<tbody>{''.join(body) or '<tr><td colspan="4">None</td></tr>'}</tbody>"
                "</table>"
            )

        def render_finding_table(
            rows: list[dict[str, Any]], title: str, extra_previous: bool = False
        ) -> str:
            body = []
            for row in rows[:100]:
                prev_col = ""
                if extra_previous:
                    prev_col = (
                        f"<td>{html.escape(row.get('previous_severity', ''))}</td>"
                    )
                body.append(
                    "<tr>"
                    f"<td>{html.escape(row.get('asn', ''))}</td>"
                    f"<td>{html.escape(row.get('severity', ''))}</td>"
                    f"<td>{html.escape(row.get('name', ''))}</td>"
                    f"<td>{html.escape(row.get('template_id', ''))}</td>"
                    f"<td>{html.escape(row.get('target', ''))}</td>"
                    f"{prev_col}"
                    "</tr>"
                )
            header_prev = "<th>Previous severity</th>" if extra_previous else ""
            colspan = "6" if extra_previous else "5"
            return (
                f"<h2>{html.escape(title)}</h2>"
                "<table>"
                f"<thead><tr><th>ASN</th><th>Severity</th><th>Name</th><th>Template</th><th>Target</th>{header_prev}</tr></thead>"
                f"<tbody>{''.join(body) or f'<tr><td colspan="{colspan}">None</td></tr>'}</tbody>"
                "</table>"
            )

        changed_web_rows = []
        for row in diff_data.get("changed_web_assets", [])[:100]:
            locator = row.get("url") or row.get("service") or row.get("canonical") or ""
            changes_text = []
            for field_name, values in (row.get("changes") or {}).items():
                before = values.get("before")
                after = values.get("after")
                changes_text.append(f"{field_name}: {before!r} → {after!r}")
            changed_web_rows.append(
                "<tr>"
                f"<td>{html.escape(row.get('asn', ''))}</td>"
                f"<td>{html.escape(locator)}</td>"
                f"<td>{html.escape(' | '.join(changes_text))}</td>"
                "</tr>"
            )

        top_ports_html = "".join(
            f"<li>{html.escape(str(k))} — {v}</li>"
            for k, v in summary.get("top_ports", [])[:15]
        )
        top_techs_html = "".join(
            f"<li>{html.escape(str(k))} — {v}</li>"
            for k, v in summary.get("top_techs", [])[:15]
        )
        top_servers_html = "".join(
            f"<li>{html.escape(str(k))} — {v}</li>"
            for k, v in summary.get("top_servers", [])[:15]
        )

        screenshot_blocks = []
        for img in sorted(self.run_dir.rglob("*")):
            if img.suffix.lower() not in {".png", ".jpg", ".jpeg", ".webp"}:
                continue
            rel = img.relative_to(self.run_dir)
            if "screenshots" not in rel.parts:
                continue
            screenshot_blocks.append(
                f"<a href='../{html.escape(str(rel))}'><img src='../{html.escape(str(rel))}' style='max-width:280px; max-height:180px; border:1px solid #ddd;'></a>"
            )
            if len(screenshot_blocks) >= 30:
                break

        delta_banner = (
            f"<p><strong>Diff baseline:</strong> compared against previous run <code>{html.escape(previous_run_id)}</code>.</p>"
            if previous_run_id
            else "<p><strong>Diff baseline:</strong> no previous run found; this run established the baseline.</p>"
        )

        page = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>ProjectDiscovery ASN Pipeline Report</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 24px; line-height: 1.45; }}
h1, h2 {{ margin-top: 1.2em; }}
.cards {{ display:flex; flex-wrap:wrap; gap:12px; }}
.card {{ border:1px solid #ddd; border-radius:10px; padding:12px 16px; min-width:180px; background:#fafafa; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; vertical-align: top; }}
th {{ background: #f5f5f5; }}
ul {{ margin-top: 0.2em; }}
.gallery {{ display:flex; flex-wrap:wrap; gap:12px; }}
a {{ text-decoration:none; }}
code {{ background:#f3f3f3; padding:2px 4px; border-radius:4px; }}
</style>
</head>
<body>
<h1>ProjectDiscovery ASN Pipeline Report</h1>
<p><strong>Generated:</strong> {html.escape(summary.get("generated_at", ""))}</p>
<p><a href="raw.html">Browse all raw results</a></p>

<h2>Overview</h2>
<div class="cards">
    <div class="card"><strong>ASNs</strong><br>{counts.get("asns", 0)}</div>
    <div class="card"><strong>Open port records</strong><br>{counts.get("open_port_records", 0)}</div>
    <div class="card"><strong>Live URLs</strong><br>{counts.get("live_urls", 0)}</div>
    <div class="card"><strong>TLS records</strong><br>{counts.get("tls_records", 0)}</div>
    <div class="card"><strong>Crawled endpoints</strong><br>{counts.get("katana_records", 0)}</div>
    <div class="card"><strong>Nuclei findings</strong><br>{counts.get("nuclei_findings", 0)}</div>
</div>

<h2>What changed in this run</h2>
{delta_banner}
<div class="cards">
    <div class="card"><strong>New assets</strong><br>{diff_counts.get("new_assets", 0)}</div>
    <div class="card"><strong>Resurfaced assets</strong><br>{diff_counts.get("resurfaced_assets", 0)}</div>
    <div class="card"><strong>Changed web assets</strong><br>{diff_counts.get("changed_web_assets", 0)}</div>
    <div class="card"><strong>New interesting assets</strong><br>{diff_counts.get("new_interesting_assets", 0)}</div>
    <div class="card"><strong>New findings</strong><br>{diff_counts.get("new_findings", 0)}</div>
    <div class="card"><strong>Resurfaced findings</strong><br>{diff_counts.get("resurfaced_findings", 0)}</div>
    <div class="card"><strong>Resolved findings</strong><br>{diff_counts.get("resolved_findings", 0)}</div>
    <div class="card"><strong>Worsened findings</strong><br>{diff_counts.get("worsened_findings", 0)}</div>
</div>

{render_asset_table(diff_data.get("new_interesting_assets", []), "New interesting assets")}
{render_asset_table(diff_data.get("new_assets", []), "New assets")}
{render_asset_table(diff_data.get("resurfaced_assets", []), "Resurfaced assets")}

<h2>Changed web assets</h2>
<table>
<thead><tr><th>ASN</th><th>Asset</th><th>Changes</th></tr></thead>
<tbody>{"".join(changed_web_rows) or '<tr><td colspan="3">None</td></tr>'}</tbody>
</table>

{render_finding_table(diff_data.get("new_high_signal_findings", []), "New / resurfaced high-signal findings")}
{render_finding_table(diff_data.get("new_findings", []), "New findings")}
{render_finding_table(diff_data.get("resurfaced_findings", []), "Resurfaced findings")}
{render_finding_table(diff_data.get("resolved_findings", []), "Resolved findings")}
{render_finding_table(diff_data.get("worsened_findings", []), "Worsened findings", extra_previous=True)}

<h2>Nuclei severity</h2>
<div class="cards">
    <div class="card"><strong>Critical</strong><br>{sev.get("critical", 0)}</div>
    <div class="card"><strong>High</strong><br>{sev.get("high", 0)}</div>
    <div class="card"><strong>Medium</strong><br>{sev.get("medium", 0)}</div>
    <div class="card"><strong>Low</strong><br>{sev.get("low", 0)}</div>
    <div class="card"><strong>Info</strong><br>{sev.get("info", 0)}</div>
</div>

<h2>Per-ASN summary</h2>
<table>
<thead>
<tr><th>ASN</th><th>CIDRs</th><th>PTR</th><th>Ports</th><th>Live URLs</th><th>TLS</th><th>Katana</th><th>Nuclei</th></tr>
</thead>
<tbody>{"".join(asn_rows)}</tbody>
</table>

<h2>Most important findings</h2>
<table>
<thead><tr><th>ASN</th><th>Severity</th><th>Name</th><th>Template</th><th>Target</th></tr></thead>
<tbody>{"".join(finding_rows) or '<tr><td colspan="5">No findings.</td></tr>'}</tbody>
</table>

<h2>Interesting web assets</h2>
<table>
<thead><tr><th>ASN</th><th>URL</th><th>Status</th><th>Title</th><th>Tech</th></tr></thead>
<tbody>{"".join(interesting_rows) or '<tr><td colspan="5">No interesting assets matched the heuristic.</td></tr>'}</tbody>
</table>

<h2>Top observed signals</h2>
<div class="cards">
    <div class="card"><strong>Top ports</strong><ul>{top_ports_html or "<li>None</li>"}</ul></div>
    <div class="card"><strong>Top technologies</strong><ul>{top_techs_html or "<li>None</li>"}</ul></div>
    <div class="card"><strong>Top servers</strong><ul>{top_servers_html or "<li>None</li>"}</ul></div>
</div>

<h2>Screenshot gallery</h2>
<div class="gallery">
{"".join(screenshot_blocks) or "<p>No screenshots captured.</p>"}
</div>

</body>
</html>
"""
        write_text(self.report_dir / "index.html", page)


# =========================
# CLI
# =========================


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Production-ready ProjectDiscovery ASN pipeline"
    )
    p.add_argument("--config", required=True, help="Path to JSON config file")
    p.add_argument(
        "--run-dir", help="Existing run directory to resume, or new directory to use"
    )
    return p.parse_args()


def build_run_dir(cfg: PipelineConfig, run_dir_arg: str | None) -> Path:
    if run_dir_arg:
        rd = Path(run_dir_arg).resolve()
        rd.mkdir(parents=True, exist_ok=True)
        return rd
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
    rd = Path(cfg.output_root).resolve() / ts
    rd.mkdir(parents=True, exist_ok=True)
    return rd


def main() -> int:
    args = parse_args()
    cfg = PipelineConfig.from_json(args.config)
    run_dir = build_run_dir(cfg, args.run_dir)

    lock_path = run_dir / ".lock"
    pipeline: Pipeline | None = None

    try:
        with FileLock(lock_path):
            pipeline = Pipeline(cfg, run_dir)
            pipeline.run()
            print(f"[+] Completed: {run_dir}")
            print(f"[+] Main report: {run_dir / 'report' / 'index.html'}")
            print(f"[+] Raw browser: {run_dir / 'report' / 'raw.html'}")
        return 0
    except FileExistsError:
        print(f"[!] Run directory is already locked: {run_dir}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"[!] ERROR: {e}", file=sys.stderr)
        return 1
    finally:
        if pipeline is not None:
            pipeline.close()


if __name__ == "__main__":
    maybe_run_chunk_engine_mode()
    raise SystemExit(main())
