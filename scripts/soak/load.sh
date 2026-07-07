#!/usr/bin/env bash
# Runs on VDS-B. Hammers every URL in URLS_FILE at RATE_PER_URL rps
# for DURATION, with a global CONCURRENCY cap on in-flight requests.
#
# Per-request output goes to requests.csv:
#   ts,url,http_code,time_total,size_download
#
# Rate control is coarse — a 1-second tick fires RATE_PER_URL curls
# per URL per tick. Bursts within a tick are acceptable for soak; if
# you need smooth rate, use `oha` or `vegeta` instead of this script.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${HERE}/env"

mkdir -p "${OUT_DIR}"
REQ_CSV="${OUT_DIR}/requests.csv"

if [ ! -s "${URLS_FILE}" ]; then
  echo "URLS_FILE=${URLS_FILE} is missing or empty" >&2
  exit 1
fi

mapfile -t URLS < <(grep -vE '^\s*(#|$)' "${URLS_FILE}")
URL_COUNT=${#URLS[@]}
if [ "${URL_COUNT}" -eq 0 ]; then
  echo "no URLs after comment/blank strip" >&2
  exit 1
fi

# Header once.
if [ ! -s "${REQ_CSV}" ]; then
  echo "ts,url,http_code,time_total,size_download" > "${REQ_CSV}"
fi

# Duration → seconds.
duration_seconds() {
  local d="$1"
  case "$d" in
    *h) echo "$(( ${d%h} * 3600 ))" ;;
    *m) echo "$(( ${d%m} * 60 ))" ;;
    *s) echo "${d%s}" ;;
    *)  echo "$d" ;;
  esac
}

TOTAL_S=$(duration_seconds "${DURATION}")
END_TS=$(( $(date +%s) + TOTAL_S ))

echo "[soak/load] ${URL_COUNT} url(s), ${RATE_PER_URL} rps/url, C=${CONCURRENCY}, dur=${DURATION}"
echo "[soak/load] output: ${REQ_CSV}"

trap 'echo "[soak/load] stopping"; exit 0' INT TERM

# Semaphore via a FIFO to cap concurrency without spawning per-tick
# processes.
SEM=$(mktemp -u)
mkfifo "${SEM}"
exec 3<>"${SEM}"
rm "${SEM}"
for _ in $(seq 1 "${CONCURRENCY}"); do echo "" >&3; done

fire() {
  local url="$1"
  local ts
  ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  local line
  # -o /dev/null: drop body. -w: emit code,time,bytes.
  line=$(curl -sS -o /dev/null \
    --max-time "${CURL_TIMEOUT}" \
    -w '%{http_code},%{time_total},%{size_download}' \
    "${url}" 2>/dev/null || echo "000,0,0")
  echo "${ts},${url},${line}" >> "${REQ_CSV}"
  # Release semaphore slot.
  echo "" >&3
}

while [ "$(date +%s)" -lt "${END_TS}" ]; do
  tick_start=$(date +%s)
  for url in "${URLS[@]}"; do
    for _ in $(seq 1 "${RATE_PER_URL}"); do
      # Acquire slot.
      read -r -u 3
      fire "${url}" &
    done
  done
  # Sleep to next tick (target: 1 tick/s).
  now=$(date +%s)
  drift=$(( 1 - (now - tick_start) ))
  if [ "${drift}" -gt 0 ]; then
    sleep "${drift}"
  fi
done

echo "[soak/load] waiting for in-flight requests to drain"
wait
echo "[soak/load] done"
