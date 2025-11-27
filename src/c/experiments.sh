#!/usr/bin/env bash
set -euo pipefail

MAP_PATH="/sys/fs/bpf/maps/tb_map"
KEY=1
BIN="./xdp_network/change_tb_limit.sh"
bpftool map update name impacted_qp key hex 00 00 00 00 value hex 00 00 00 00

sleep 5
sudo "$BIN" 10 "$MAP_PATH" "$KEY"

sleep 0.003
sudo "$BIN" 1000000000 "$MAP_PATH" "$KEY"

sleep 5 
sudo "$BIN" 10 "$MAP_PATH" "$KEY"

sleep 0.003
sudo "$BIN" 1000000000 "$MAP_PATH" "$KEY"

sleep 5 
sudo "$BIN" 10 "$MAP_PATH" "$KEY"


