#!/usr/bin/env bash
# Runs on VDS-A alongside krot-server.
#
# Every SCRAPE_INTERVAL seconds:
#   1. curls the /metrics endpoint, extracts the counters we care
#      about, appends one row to metrics.csv.
#   2. reads /proc/<pid>/status for RSS/VmSize, appends to process.csv.
#
# Both CSVs are keyed by the wall-clock timestamp so `report.sh` can
# join them.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${HERE}/env"

mkdir -p "${OUT_DIR}"
METRICS_CSV="${OUT_DIR}/metrics.csv"
PROCESS_CSV="${OUT_DIR}/process.csv"

# Counters we sample. Add more here if you want them in the report.
COUNTERS=(
  krot_uptime_seconds
  krot_handshake_ok_total
  krot_handshake_bad_signature_total
  krot_session_bye_total
  krot_session_dropped_total
  krot_tunnels_live
  krot_tunnels_dangling
  krot_rate_limit_quota_exceeded_total
  krot_transport_quic_accepted_total
  krot_transport_tcp_fallback_accepted_total
  krot_bytes_period_used
)

# CSV header — written once if file is empty.
init_header() {
  local path="$1"; shift
  local header="ts,$(IFS=,; echo "$*")"
  if [ ! -s "$path" ]; then
    echo "$header" > "$path"
  fi
}

init_header "${METRICS_CSV}" "${COUNTERS[@]}"
init_header "${PROCESS_CSV}" pid rss_kb vmsize_kb threads open_fds

find_server_pid() {
  # Best-effort: single krot-server on the host. Override by exporting
  # KROT_SERVER_PID before running.
  if [ -n "${KROT_SERVER_PID:-}" ]; then
    echo "${KROT_SERVER_PID}"
    return
  fi
  pgrep -x krot-server | head -1
}

scrape_metrics() {
  local ts="$1"
  local body
  body=$(curl -sS --max-time 5 \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    "${ADMIN_URL}/metrics" || true)
  if [ -z "${body}" ]; then
    echo "warn: /metrics scrape empty at ${ts}" >&2
    return
  fi
  local row="${ts}"
  local name value
  for name in "${COUNTERS[@]}"; do
    # First non-comment line matching `^name` — strip labels for
    # simplicity (soak workload has few labels).
    value=$(echo "${body}" \
      | awk -v n="${name}" '$1 ~ "^"n"($|{)" && $1 !~ "^#" {print $2; exit}')
    row="${row},${value:-NA}"
  done
  echo "${row}" >> "${METRICS_CSV}"
}

scrape_process() {
  local ts="$1"
  local pid
  pid=$(find_server_pid)
  if [ -z "${pid}" ]; then
    echo "warn: krot-server pid not found at ${ts}" >&2
    return
  fi
  local status="/proc/${pid}/status"
  if [ ! -r "${status}" ]; then
    return
  fi
  local rss vmsize threads fds
  rss=$(awk '/^VmRSS:/ {print $2}' "${status}")
  vmsize=$(awk '/^VmSize:/ {print $2}' "${status}")
  threads=$(awk '/^Threads:/ {print $2}' "${status}")
  fds=$(ls "/proc/${pid}/fd" 2>/dev/null | wc -l)
  echo "${ts},${pid},${rss:-NA},${vmsize:-NA},${threads:-NA},${fds:-NA}" \
    >> "${PROCESS_CSV}"
}

echo "[soak/server] scraping every ${SCRAPE_INTERVAL}s → ${OUT_DIR}"
echo "[soak/server] ctrl-c to stop"

trap 'echo "[soak/server] stopping"; exit 0' INT TERM

while true; do
  ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  scrape_metrics "${ts}"
  scrape_process "${ts}"
  sleep "${SCRAPE_INTERVAL}"
done
