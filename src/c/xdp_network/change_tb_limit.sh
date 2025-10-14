#!/usr/bin/env bash
# configure_tb_rate_be.sh <rate_Mbit> [tb_map_path] [key]
# Writes tb_map value as BIG-ENDIAN bytes:
# struct tb_state { u64 tokens; u64 last_ns; u64 rate_q32; u64 burst; }

set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: $0 <rate_Mbit> [tb_map_path] [key]" >&2
  exit 1
fi

RATE_MBIT=$1
TBMAP_PATH=${2:-/sys/fs/bpf/maps/tb_map}
KEY=${3:-0}
BURST=$((1024*1024))   # 1 MiB

# Q0.32: bytes/ns * 2^32  where bytes/ns = (Mbit/s * 1e6 / 8) / 1e9
rate_q32=$(awk -v m="$RATE_MBIT" 'BEGIN { printf("%d\n", (m*1e6/8/1e9) * (2^32)); }')

# Print u64 as 8 big-endian bytes (always 16 hex with leading zeros)
to_be64() {
  local v
  v=$(printf "%016x" "$1")
  echo "${v:14:2} ${v:12:2} ${v:10:2} ${v:8:2} ${v:6:2} ${v:4:2} ${v:2:2} ${v:0:2}"
}

zeros_be="00 00 00 00 00 00 00 00"
rate_be="$(to_be64 "$rate_q32")"
burst_be="$(to_be64 "$BURST")"
key_be=$(printf "%02x 00 00 00" "$KEY")

echo "[+] tb_map=$TBMAP_PATH  key=$KEY  rate=${RATE_MBIT}Mbit/s  rate_q32=$rate_q32"
sudo bpftool map update pinned "$TBMAP_PATH" \
  key hex $key_be \
  value hex \
    $zeros_be \
    $zeros_be \
    $rate_be \
    $burst_be
echo "[✓] Updated."

echo $rate_be
echo $burst_be