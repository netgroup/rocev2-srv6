#!/bin/bash
set -eux

readonly BPFTOOL="bpftool"
readonly OBJ_PATH="../../src/c/.output/"
readonly BPFFS_PATH="/sys/fs/bpf"

# Interfacce
VETH_GW1_GW2="veth-gw1-gw2"
BF_PORT="ens11np0"

# MAC e indirizzi
MAC_SRC="02:aa:bb:cc:11:00"   # gw1
MAC_DST="02:aa:bb:cc:22:00"   # gw2
IFINDEX=$(cat /sys/class/net/${BF_PORT}/ifindex)

# SID singolo hop (gw1 -> gw2)
SID_GW2="fc f0 00 00 00 b2 00 d4 00 00 00 00 00 00 00 00"

disable_checksum_offload() {
    local ifname="${1}"
    for i in $(ethtool -k "${ifname}" | grep -E "(tx|rx)-checksum" | awk '{print $1}' | cut -d':' -f1); do
        ethtool -K "${ifname}" "$i" off || true
    done
}

disable_checksum_offload ${VETH_GW1_GW2}
disable_checksum_offload ${BF_PORT}

# mount fs e setup
mount -t bpf bpf "${BPFFS_PATH}" 2>/dev/null || true
mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null || true
mkdir -p "${BPFFS_PATH}"/{progs,maps}
ulimit -l unlimited

# Caricamento XDP
${BPFTOOL} prog loadall \
	"${OBJ_PATH}/xdp.bpf.o" /sys/fs/bpf/progs \
	pinmaps /sys/fs/bpf/maps \
	type xdp

# Attach
${BPFTOOL} net detach xdp dev ${VETH_GW1_GW2} 2>/dev/null || true
${BPFTOOL} net attach xdpdrv pinned "${BPFFS_PATH}/progs/xdp_sr6decap" dev ${VETH_GW1_GW2}

${BPFTOOL} net detach xdp dev ${BF_PORT} 2>/dev/null || true
${BPFTOOL} net attach xdpdrv pinned "${BPFFS_PATH}/progs/xdp_sr6encap" dev ${BF_PORT}

# Popola sr6decap_table
${BPFTOOL} map update pinned "${BPFFS_PATH}/maps/sr6decap_table" \
	key hex ${SID_GW2} \
	value hex 64 00 00 00 00 00 00 00

# Popola sr6encap_ip4_table
${BPFTOOL} map update pinned "${BPFFS_PATH}/maps/sr6encap_ip4_table" \
	key hex 01 02 37 0a \
	value hex \
	  fd 00 00 a1 00 b0 00 00 00 00 00 00 00 00 00 01 \
	  fc f0 00 00 00 a2 00 d4 00 00 00 00 00 00 00 00

# Popola route_map
${BPFTOOL} map update pinned "${BPFFS_PATH}/maps/xdp_route_map" \
	key hex ${SID_GW2} \
	value hex \
	  $(printf "%08x" ${IFINDEX} | sed 's/../& /g') \
	  $(echo ${MAC_SRC} | sed 's/:/ /g') \
	  $(echo ${MAC_DST} | sed 's/:/ /g')

echo "[gw1] configurato single-hop encap/decap verso gw2"
