#!/usr/bin/env bash
set -euo pipefail

# Configurazione mappe e bin
MAP_NAME="impacted_qp"                 # mappa dove key=0 contiene il QP impacted (u32)
KEY_BYTES_HEX="00 00 00 00"            # chiave 0 in hex per bpftool
TB_MAP_PATH="/sys/fs/bpf/maps/tb_map"  # mappa token bucket pin-ata
TB_KEY="1"                             # path_id da limitare
BIN="./xdp_network/change_tb_limit.sh" # script per aggiornare rate in tb_map

# Finestra di stabilità del nuovo QP e durata minima del LOW
STABLE_WINDOW_SEC=5                    # il nuovo QP deve restare uguale per >= 5 s
MIN_LOW_HOLD_SEC=0.300                 # LOW deve rimanere almeno 300 ms

# Polling
POLL_INTERVAL_SEC=0.2

# Valori di rate
LOW_RATE_BITS=10
HIGH_RATE_BITS=1000000000

last_qp=""
last_change_ts=0
applied_for_qp=""
lowrate_applied_ts=0

now_ts() { date +%s; }

read_impacted_qp() {
  # Leggi impacted_qp[0] in JSON e converti i byte del value in una stringa esadecimale stabile
  local out bytes
  if ! out=$(sudo bpftool -jp map lookup name "$MAP_NAME" key hex $KEY_BYTES_HEX 2>/dev/null); then
    echo "0x00000000"; return
  fi
  bytes=$(jq -r '.value | map(.[2:]) | join("")' <<<"$out")
  printf "0x%08x\n" "0x${bytes:-00000000}"
}

apply_low_rate() {
  echo "[info] -> LOW $LOW_RATE_BITS on path_id=$TB_KEY (tb_map=$TB_MAP_PATH)"
  sudo "$BIN" "$LOW_RATE_BITS" "$TB_MAP_PATH" "$TB_KEY"
}

apply_high_rate() {
  echo "[info] -> HIGH $HIGH_RATE_BITS on path_id=$TB_KEY (tb_map=$TB_MAP_PATH)"
  sudo "$BIN" "$HIGH_RATE_BITS" "$TB_MAP_PATH" "$TB_KEY"
}

# opzionale: inizializza impacted_qp[0] a 0
sudo bpftool map update name "$MAP_NAME" key hex $KEY_BYTES_HEX value hex 00 00 00 00

echo "[info] Attendo cambio QP impacted, stabilità ${STABLE_WINDOW_SEC}s; LOW deve durare >= ${MIN_LOW_HOLD_SEC}s"

while true; do
  cur_qp=$(read_impacted_qp)
  t=$(now_ts)

  if [[ -z "$last_qp" ]]; then
    last_qp="$cur_qp"
    last_change_ts="$t"
  fi

  if [[ "$cur_qp" != "$last_qp" && "$cur_qp" != "0x00000000" ]]; then
    echo "[info] impacted_qp cambiato: $last_qp -> $cur_qp at $(date)"
    last_qp="$cur_qp"
    last_change_ts="$t"
    applied_for_qp=""
    lowrate_applied_ts=0
  fi

  # Quando il QP è stabile per >= STABLE_WINDOW_SEC, applica LOW una sola volta
  if [[ "$last_qp" != "0x00000000" ]]; then
    stable_for=$(( t - last_change_ts ))
    if (( stable_for >= STABLE_WINDOW_SEC )); then
      if [[ "$applied_for_qp" != "$last_qp" ]]; then
        apply_low_rate
        applied_for_qp="$last_qp"
        lowrate_applied_ts=$(date +%s%3N)   # millisecondi epoch
      fi
    fi
  fi

  # Mantieni LOW per almeno 300 ms, poi risali a HIGH
  if [[ "$lowrate_applied_ts" != "0" ]]; then
    now_ms=$(date +%s%3N)
    held_ms=$(( now_ms - lowrate_applied_ts ))
    if (( held_ms >= 300 )); then
      apply_high_rate
      lowrate_applied_ts=0
    fi
  fi

  sleep "$POLL_INTERVAL_SEC"
done

