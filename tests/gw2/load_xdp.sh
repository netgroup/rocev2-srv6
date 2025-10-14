#!/bin/bash
# XDP load per gw2 (decapsulamento IPv6→IPv4)

readonly BPFTOOL="bpftool"
readonly OBJ_PATH="../../src/c/.output/"
readonly BPFFS_PATH="/sys/fs/bpf"
readonly DEV="ens9np1"

mount -t bpf bpf "${BPFFS_PATH}" 2>/dev/null || true
mkdir -p "${BPFFS_PATH}"/{progs,maps}

# Carica il programma XDP
${BPFTOOL} prog loadall \
    "${OBJ_PATH}/xdp.bpf.o" /sys/fs/bpf/progs \
    pinmaps /sys/fs/bpf/maps \
    type xdp

# Attacca il programma decap
${BPFTOOL} net attach xdpdrv \
    pinned "${BPFFS_PATH}/progs/xdp_sr6decap" \
    dev ${DEV}

# Aggiungi SID di decapsulamento
${BPFTOOL} map update \
    pinned "${BPFFS_PATH}/maps/sr6decap_table" \
    key hex fc f0 00 00 00 a1 00 d4 00 00 00 00 00 00 00 00 \
    value hex 64 00 00 00 00 00 00 00

echo "[gw2] XDP decap caricato su ${DEV}"

