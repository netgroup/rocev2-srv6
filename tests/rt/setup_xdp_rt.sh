readonly BPFTOOL="bpftool"
readonly OBJ_PATH="../../src/c/.output/"
readonly BPFFS_PATH="/sys/fs/bpf"

VETH_RT1_1="veth-rt1-gw1"
VETH_RT1_2="veth-rt1-gw2"
VETH_RT2_1="veth-rt2-gw1"
VETH_RT2_2="veth-rt2-gw2"


###############
##### rt1 #####
###############

set +e
read -r -d '' rt1_env <<-EOF
	mount -t bpf bpf "${BPFFS_PATH}"
	mount -t tracefs nodev /sys/kernel/tracing

	# It allows to load maps with many entries without failing
	ulimit -l unlimited

	mkdir "${BPFFS_PATH}"/{progs,maps}

	${BPFTOOL} prog loadall \
		"${OBJ_PATH}/xdp.bpf.o" /sys/fs/bpf/progs \
		pinmaps /sys/fs/bpf/maps \
		type xdp

	${BPFTOOL} net attach xdpdrv \
		pinned "${BPFFS_PATH}/progs/xdp_pass" \
		dev ${VETH_RT1_1}

	${BPFTOOL} net attach xdpdrv \
		pinned "${BPFFS_PATH}/progs/xdp_pass" \
		dev ${VETH_RT1_2}

EOF
set -e

###############
##### rt2 #####
###############

set +e
read -r -d '' rt2_env <<-EOF
	mount -t bpf bpf "${BPFFS_PATH}"
	mount -t tracefs nodev /sys/kernel/tracing

	# It allows to load maps with many entries without failing
	ulimit -l unlimited

	mkdir "${BPFFS_PATH}"/{progs,maps}

	${BPFTOOL} prog loadall \
		"${OBJ_PATH}/xdp.bpf.o" /sys/fs/bpf/progs \
		pinmaps /sys/fs/bpf/maps \
		type xdp

	${BPFTOOL} net attach xdpdrv \
		pinned "${BPFFS_PATH}/progs/xdp_pass" \
		dev ${VETH_RT2_1}

	${BPFTOOL} net attach xdpdrv \
		pinned "${BPFFS_PATH}/progs/xdp_pass" \
		dev ${VETH_RT2_2}

EOF
set -e


sudo ip netns exec rt1 bash -c "${rt1_env}"
sudo ip netns exec rt2 bash -c "${rt2_env}"
