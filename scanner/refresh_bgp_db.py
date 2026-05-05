#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from mrtparse import Reader, MRT_T, TD_V2_ST, BGP_ATTR_T


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def asn_to_num(value: str) -> str:
    value = value.strip().upper()
    if value.startswith("AS"):
        value = value[2:]
    return value


def enum_value(value):
    if isinstance(value, (int, str)):
        return value
    try:
        return list(value)[0]
    except Exception:
        return value


def flatten_as_path_segments(value) -> list[str]:
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


def origin_as_from_path_attributes(path_attributes) -> str | None:
    as_path: list[str] = []
    as4_path: list[str] = []

    for attr in path_attributes or []:
        attr_type = enum_value(attr.get("type"))
        if attr_type == BGP_ATTR_T["AS_PATH"]:
            as_path = flatten_as_path_segments(attr.get("value", []))
        elif attr_type == BGP_ATTR_T["AS4_PATH"]:
            as4_path = flatten_as_path_segments(attr.get("value", []))

    merged = as4_path or as_path
    return merged[-1] if merged else None


def download_to_cache(url: str, dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = Request(url, headers={"User-Agent": "asn-prefix-db/1.0"})
    with urlopen(req, timeout=300) as resp, dest.open("wb") as out:
        shutil.copyfileobj(resp, out)
    return dest


def resolve_source(source: dict[str, str], cache_dir: Path) -> tuple[str, Path]:
    kind = source.get("kind", "path").strip().lower()
    value = source.get("value", "").strip()
    if not value:
        raise RuntimeError("Invalid bgp_mrt_sources entry: missing value")

    if kind == "path":
        path = Path(value)
        if not path.exists():
            raise RuntimeError(f"BGP MRT file not found: {path}")
        return value, path

    if kind == "url":
        parsed = urlparse(value)
        filename = Path(parsed.path).name or "snapshot.mrt"
        dest = cache_dir / filename
        download_to_cache(value, dest)
        return value, dest

    raise RuntimeError(f"Unsupported source kind: {kind}")


def parse_mrt_into_db(mrt_path: Path, conn: sqlite3.Connection, source_name: str) -> None:
    batch: list[tuple[str, str]] = []

    def flush() -> None:
        nonlocal batch
        if not batch:
            return
        conn.executemany(
            "INSERT OR IGNORE INTO current_asn_prefixes_new(asn, prefix) VALUES(?, ?)",
            batch,
        )
        batch = []

    for entry in Reader(str(mrt_path)):
        if getattr(entry, "err", None):
            continue

        m = entry.data
        mrt_type = enum_value(m.get("type"))

        if mrt_type == MRT_T["TABLE_DUMP"]:
            prefix = f"{m['prefix']}/{m['length']}"
            origin_as = origin_as_from_path_attributes(m.get("path_attributes", []))
            if origin_as:
                batch.append((origin_as, prefix))

        elif mrt_type == MRT_T["TABLE_DUMP_V2"]:
            subtype = enum_value(m.get("subtype"))

            if subtype == TD_V2_ST["PEER_INDEX_TABLE"]:
                continue

            if "prefix" not in m or "rib_entries" not in m:
                continue

            prefix = f"{m['prefix']}/{m['length']}"

            for rib_entry in m.get("rib_entries", []):
                origin_as = origin_as_from_path_attributes(rib_entry.get("path_attributes", []))
                if origin_as:
                    batch.append((origin_as, prefix))
                    break

        if len(batch) >= 10000:
            flush()

    flush()


def table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return row is not None


def rebuild_db(db_path: Path, config_path: Path) -> None:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    sources = config.get("bgp_mrt_sources", [])
    if not sources:
        raise RuntimeError("bgp_mrt_sources is empty")

    cache_dir = ensure_dir(Path(config.get("bgp_cache_dir", "./state/bgp-cache")))
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")

    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS refresh_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            source_count INTEGER NOT NULL DEFAULT 0,
            prefix_count INTEGER NOT NULL DEFAULT 0
        );
        """
    )

    started_at = utc_now()
    conn.execute(
        "INSERT INTO refresh_history(started_at, source_count, prefix_count) VALUES(?, 0, 0)",
        (started_at,),
    )
    refresh_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    conn.execute("DROP TABLE IF EXISTS current_asn_prefixes_new")
    conn.execute(
        """
        CREATE TABLE current_asn_prefixes_new (
            asn TEXT NOT NULL,
            prefix TEXT NOT NULL,
            PRIMARY KEY (asn, prefix)
        )
        """
    )

    resolved_sources: list[tuple[str, Path]] = []
    for source in sources:
        resolved_sources.append(resolve_source(source, cache_dir))

    for source_name, local_path in resolved_sources:
        parse_mrt_into_db(local_path, conn, source_name)
        conn.commit()

    prefix_count = conn.execute(
        "SELECT COUNT(*) FROM current_asn_prefixes_new"
    ).fetchone()[0]

    conn.execute("BEGIN IMMEDIATE")
    try:
        if table_exists(conn, "current_asn_prefixes"):
            conn.execute("ALTER TABLE current_asn_prefixes RENAME TO current_asn_prefixes_old")

        conn.execute("ALTER TABLE current_asn_prefixes_new RENAME TO current_asn_prefixes")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_current_asn_prefixes_asn ON current_asn_prefixes(asn)")
        conn.execute("DROP TABLE IF EXISTS current_asn_prefixes_old")

        conn.execute(
            "INSERT INTO meta(key, value) VALUES('last_refresh_at', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (utc_now(),),
        )
        conn.execute(
            "INSERT INTO meta(key, value) VALUES('last_prefix_count', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(prefix_count),),
        )
        conn.execute(
            "UPDATE refresh_history SET finished_at=?, source_count=?, prefix_count=? WHERE id=?",
            (utc_now(), len(resolved_sources), prefix_count, refresh_id),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Refresh local ASN->CIDR SQLite database from MRT dumps")
    parser.add_argument("--config", required=True, help="Path to JSON config file")
    parser.add_argument("--db", required=True, help="Path to SQLite DB to build")
    args = parser.parse_args()

    rebuild_db(Path(args.db), Path(args.config))
    print(f"[+] ASN DB refreshed: {args.db}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
