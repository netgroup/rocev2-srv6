#!/bin/bash

readonly BPFTOOL="bpftool"
readonly OBJ_PATH="../../src/c/.output/"
readonly BPFFS_PATH="/sys/fs/bpf"

readonly ECN_MARK=yes

if ! command -v "${BPFTOOL}" &>/dev/null; then
    echo "bpftool program is not available"
    exit 1
fi

disable_checksum_offload()
{
	local ifname="${1}"

	for i in $(ethtool -k "${ifname}" | \
		   grep -E "(tx|rx)-checksum" | \
		   awk '{print $1}' | \
		   cut -d':' -f1); do
		ethtool -K "${ifname}" "${i}" off || \
		true;
	done
}

# Interface mapping based on dynamic veth pair naming
VETH_GW1_RT1="veth-gw1-rt1"
VETH_GW1_RT2="veth-gw1-rt2"
BF_PORT="ens11np0"

disable_checksum_offload ${VETH_GW1_RT1}
disable_checksum_offload ${VETH_GW1_RT2}

# Use existing namespaces from virtual_network.sh
ip netns list | grep -E "gw1|rt1|rt2|gw2" || { echo "Namespaces missing! Run virtual_network.sh first."; exit 1; }
mount -t bpf bpf "${BPFFS_PATH}"
mount -t tracefs nodev /sys/kernel/tracing

# It allows to load maps with many entries without failing
ulimit -l unlimited

mkdir "${BPFFS_PATH}"/{progs,maps}

${BPFTOOL} prog loadall \
	"${OBJ_PATH}/xdp.bpf.o" /sys/fs/bpf/progs \
	pinmaps /sys/fs/bpf/maps \
	type xdp

###################
###### VETH1 ######
###################


# required otherwise redirect (on the other peer) for veth won't work
${BPFTOOL} net attach xdpdrv \
	pinned "${BPFFS_PATH}/progs/xdp_sr6decap" \
	dev ${VETH_GW1_RT1}

# decap SID (in bytes)
# key:
# 	0-15:	SID 				(fc01:0:0512::)
# value:
# 	0-3: table id (100)
# 	4-7: reserved
${BPFTOOL} \
	map update \
	pinned "${BPFFS_PATH}/maps/sr6decap_table"			\
	key hex         fc f0 00 00 00 a1 00 d4 00 00 00 00 00 00 00 00 \
	value hex       64 00 00 00 \
			00 00 00 00

###################
###### VETH2 ######
###################


# required otherwise redirect (on the other peer) for veth won't work
${BPFTOOL} net attach xdpdrv \
	pinned "${BPFFS_PATH}/progs/xdp_sr6decap" \
	dev ${VETH_GW1_RT2}


###################
###### BF_PORT ######
###################


${BPFTOOL} net attach xdpdrv \
	pinned "${BPFFS_PATH}/progs/xdp_sr6encap" \
	dev ${BF_PORT}

# encap policy (in bytes)
# key:
# 	0-3:	ipv4 dst address		(10.0.2.1)
# value:
# 	0-7:	ipv6 Source tunnel address	(fd00:a1:b0::1)
# 	8-15:	ipv6 Destination uSID carrier	(fc00:0:0512::)
${BPFTOOL} \
	map update \
	pinned "${BPFFS_PATH}/maps/sr6encap_ip4_table"			\
	key hex         01 02 37 0a                                     \
	value hex       fd 00 00 a1 00 b0 00 00 00 00 00 00 00 00 00 01 \
					fc f0 00 00 00 a1 00 0e 00 a2 00 d4 00 00 00 00
/bin/bash
