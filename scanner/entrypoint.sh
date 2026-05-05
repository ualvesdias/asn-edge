#!/bin/sh
set -eu

CONFIG_FILE="${CONFIG_FILE:-/config/config.json}"

mkdir -p /data /state

if [ ! -f "$CONFIG_FILE" ]; then
  echo "[-] Missing config file: $CONFIG_FILE" >&2
  exit 1
fi

if [ -n "${RUN_DIR:-}" ]; then
  exec python3 /app/pd_pipeline_pro.py --config "$CONFIG_FILE" --run-dir "$RUN_DIR"
else
  exec python3 /app/pd_pipeline_pro.py --config "$CONFIG_FILE"
fi
