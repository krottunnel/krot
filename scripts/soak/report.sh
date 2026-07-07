#!/usr/bin/env bash
# Post-processes the CSVs written by server.sh + load.sh and prints a
# human-readable summary. Also flags the classic soak regressions:
#   - Server RSS trending up over time (leak).
#   - Dangling tunnels counter growing (cleanup failure).
#   - p99 client latency growing over time (queue buildup).
#   - Non-2xx rate above 1% (breakage).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${HERE}/env"

REQ_CSV="${OUT_DIR}/requests.csv"
PROC_CSV="${OUT_DIR}/process.csv"
METRICS_CSV="${OUT_DIR}/metrics.csv"

section() { echo; echo "== $1 =="; }

# ---------- client-side ----------
if [ -s "${REQ_CSV}" ]; then
  section "requests (client, ${REQ_CSV})"
  total=$(($(wc -l < "${REQ_CSV}") - 1))
  ok=$(awk -F, 'NR>1 && $3 ~ /^2/ {n++} END{print n+0}' "${REQ_CSV}")
  err=$(awk -F, 'NR>1 && $3 !~ /^2/ {n++} END{print n+0}' "${REQ_CSV}")
  echo "total:  ${total}"
  echo "2xx:    ${ok}"
  echo "non-2xx:${err}"
  if [ "${total}" -gt 0 ]; then
    err_pct=$(awk -v e="${err}" -v t="${total}" 'BEGIN{printf "%.3f", 100*e/t}')
    echo "err%:   ${err_pct}"
    if awk "BEGIN{exit !(${err_pct} > 1.0)}"; then
      echo "⚠ non-2xx rate above 1% — investigate"
    fi
  fi

  # Percentiles across the whole run.
  awk -F, 'NR>1 {print $4}' "${REQ_CSV}" | sort -n > "${OUT_DIR}/.lat.tmp"
  n=$(wc -l < "${OUT_DIR}/.lat.tmp")
  if [ "${n}" -gt 0 ]; then
    p() {
      local q="$1"
      awk -v n="${n}" -v q="${q}" 'NR==int(n*q){printf "%.3fs\n", $1; exit}' \
        "${OUT_DIR}/.lat.tmp"
    }
    echo "latency (all requests):"
    echo "  p50: $(p 0.50)"
    echo "  p90: $(p 0.90)"
    echo "  p95: $(p 0.95)"
    echo "  p99: $(p 0.99)"
    echo "  max: $(tail -1 "${OUT_DIR}/.lat.tmp") s"
  fi

  # Latency drift: p99 of first quartile vs last quartile.
  # If last-quartile p99 is >2x first-quartile p99, flag it.
  first_q=$(( total / 4 ))
  last_q=$(( total * 3 / 4 ))
  if [ "${first_q}" -gt 100 ]; then
    p99_first=$(awk -F, -v end="${first_q}" \
      'NR>1 && NR<=end+1 {print $4}' "${REQ_CSV}" \
      | sort -n | awk -v n="${first_q}" 'NR==int(n*0.99){print; exit}')
    p99_last=$(awk -F, -v start="${last_q}" \
      'NR>start+1 {print $4}' "${REQ_CSV}" \
      | sort -n | awk -v n="${first_q}" 'NR==int(n*0.99){print; exit}')
    echo "p99 drift: first-quartile=${p99_first}s, last-quartile=${p99_last}s"
    if [ -n "${p99_first}" ] && [ -n "${p99_last}" ]; then
      if awk "BEGIN{exit !(${p99_last} > 2*${p99_first} && ${p99_first} > 0)}"; then
        echo "⚠ p99 more than doubled — likely queue buildup or leak"
      fi
    fi
  fi
  rm -f "${OUT_DIR}/.lat.tmp"
fi

# ---------- server-side process ----------
if [ -s "${PROC_CSV}" ]; then
  section "process (server, ${PROC_CSV})"
  samples=$(($(wc -l < "${PROC_CSV}") - 1))
  echo "samples: ${samples}"
  first_rss=$(awk -F, 'NR==2 {print $3; exit}' "${PROC_CSV}")
  last_rss=$(awk -F, 'END {print $3}' "${PROC_CSV}")
  first_fds=$(awk -F, 'NR==2 {print $6; exit}' "${PROC_CSV}")
  last_fds=$(awk -F, 'END {print $6}' "${PROC_CSV}")
  echo "RSS:  first=${first_rss} kB → last=${last_rss} kB"
  echo "FDs:  first=${first_fds} → last=${last_fds}"
  if [ -n "${first_rss}" ] && [ -n "${last_rss}" ] && [ "${first_rss}" -gt 0 ]; then
    delta=$(( last_rss - first_rss ))
    pct=$(awk -v d="${delta}" -v f="${first_rss}" 'BEGIN{printf "%.1f", 100*d/f}')
    echo "RSS drift: ${delta} kB (${pct}%)"
    if awk "BEGIN{exit !(${pct} > 20.0)}"; then
      echo "⚠ RSS grew more than 20% during run — probable leak"
    fi
  fi
  if [ -n "${first_fds}" ] && [ -n "${last_fds}" ]; then
    if [ "${last_fds}" -gt "$(( first_fds * 2 ))" ] && [ "${first_fds}" -gt 10 ]; then
      echo "⚠ open FD count more than doubled — probable socket leak"
    fi
  fi
fi

# ---------- server-side counters ----------
if [ -s "${METRICS_CSV}" ]; then
  section "metrics (server, ${METRICS_CSV})"
  header=$(head -1 "${METRICS_CSV}")
  # Column index for a few interesting counters.
  col() { echo "${header}" | awk -F, -v n="$1" '{for(i=1;i<=NF;i++) if($i==n) print i}'; }
  dangling_col=$(col krot_tunnels_dangling)
  bad_sig_col=$(col krot_handshake_bad_signature_total)
  quota_col=$(col krot_rate_limit_quota_exceeded_total)
  live_col=$(col krot_tunnels_live)

  print_delta() {
    local label="$1" c="$2"
    if [ -n "${c}" ]; then
      local first last
      first=$(awk -F, -v c="${c}" 'NR==2 {print $c; exit}' "${METRICS_CSV}")
      last=$(awk -F, -v c="${c}" 'END {print $c}' "${METRICS_CSV}")
      echo "${label}: first=${first} → last=${last}"
    fi
  }
  print_delta "tunnels_live         " "${live_col}"
  print_delta "tunnels_dangling     " "${dangling_col}"
  print_delta "handshake_bad_sig    " "${bad_sig_col}"
  print_delta "rate_limit_exceeded  " "${quota_col}"

  if [ -n "${dangling_col}" ]; then
    dan_first=$(awk -F, -v c="${dangling_col}" 'NR==2 {print $c; exit}' "${METRICS_CSV}")
    dan_last=$(awk -F, -v c="${dangling_col}" 'END {print $c}' "${METRICS_CSV}")
    if [ "${dan_last:-0}" -gt "$(( dan_first + 5 ))" ]; then
      echo "⚠ dangling tunnels grew by more than 5 — cleanup issue"
    fi
  fi
fi

section "done"
echo "Raw CSVs kept in ${OUT_DIR} — feel free to open in a spreadsheet."
