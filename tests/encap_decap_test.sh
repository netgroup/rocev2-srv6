#!/bin/bash

#                set CE on outer IPv6 traffic class
#  enable ECT bit                +
#      +                         |
#      |              +----------|---+     +--------------+     +--------------+
#      v              |      gw1 |   |     |      rt0     |     |      gw2     |
#  +-------+          |          |   |     |              |     |              |        +-------+
#  |   h0  |          |          v   |     |              |     |              |        |  h1   |
#  |       +----------+veth1    veth2+-----+veth3    veth4+-----+veth5    veth6+--------+       |
#  | veth0 |          |  ^       ^   |     |  ^       ^   |     |  ^       ^   |        | veth7 |
#  +-------+          |  |  (a1) |   |     |  |  (b0) |   |     |  |  (a2) |   |        +-------+
#                     |  |       |   |     |  |       |   |     |  |       |   |
# 10.0.1.1/24         +--|-------|---+     +--|-------|---+     +--|-------|---+       10.0.2.1/24
#                        |       |            |       |            |       |
#                        +       +            +       +            +       +
#                   eBPF/XDP   eBPF/XDP  eBPF/XDP   eBPF/XDP  eBPF/XDP   eBPF/XDP
#                    encap      decap     pass       pass      decap      encap
#
#

set -eu
set -x

readonly BPFTOOL="../bpftool/src/bpftool"
readonly OBJ_PATH="../src/c/.output/"
readonly BPFFS_PATH="/sys/fs/bpf"

readonly TMUX=ebpf
readonly DEBUG=off

if ! command "${BPFTOOL}" &>/dev/null; then
	echo "bpftool program is not available"
	exit 1
fi

# Kill tmux previous session
tmux kill-session -t $TMUX 2>/dev/null || true

# Clean up previous network namespaces
ip -all netns delete

ip netns add h0
ip netns add h1

ip netns add gw1
ip netns add rt0
ip netns add gw2

ip link add veth0 netns h0 type veth peer name veth1 netns gw1
ip link add veth2 netns gw1 type veth peer name veth3 netns rt0
ip link add veth4 netns rt0 type veth peer name veth5 netns gw2
ip link add veth6 netns gw2 type veth peer name veth7 netns h1


###################
#### Node: h0 #####
###################
NODE=h0
echo -e "\nNode: $NODE"
ip netns exec $NODE ip link set dev lo up
ip netns exec $NODE ip link set dev veth0 up
ip netns exec $NODE ip addr add 10.0.1.1/24 dev veth0
ip netns exec $NODE ip -4 route add default via 10.0.1.254 dev veth0

# set ECT(0)
ip netns exec $NODE \
	iptables -t mangle -A POSTROUTING \
	-d 10.0.2.1 -j TOS --set-tos 0x02/0xff

set +e
read -r -d '' h0_env <<-EOF
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
		dev veth0

	/bin/bash
EOF
set -e


####################
#### Node: gw1 #####
####################
NODE=gw1
echo -e "\nNode: $NODE"
ip netns exec $NODE sysctl -w net.ipv4.conf.all.forwarding=1
ip netns exec $NODE sysctl -w net.ipv6.conf.all.forwarding=1
# disable also rp_filter on the receiving decap interface that will forward the
# packet to the right destination (through the nexthop)
ip netns exec $NODE sysctl -w net.ipv4.conf.all.rp_filter=0
ip netns exec $NODE sysctl -w net.ipv4.conf.lo.rp_filter=0
ip netns exec $NODE sysctl -w net.ipv4.conf.default.rp_filter=0
ip netns exec $NODE sysctl -w net.ipv4.conf.veth1.rp_filter=0
ip netns exec $NODE sysctl -w net.ipv4.conf.veth2.rp_filter=0

ip netns exec $NODE ip link set dev lo up
ip netns exec $NODE ip link set dev veth1 up
ip netns exec $NODE ip link set dev veth2 up
ip netns exec $NODE ip addr add 10.0.1.254/24 dev veth1
ip netns exec $NODE ip addr add fd00:a1:b0::1/48 dev veth2

if [ "$DEBUG" == "on" ]; then
	# SRv6 microSID Encap (for DEBUG only)
	ip netns exec $NODE ip -4 route add 10.0.2.1/32 \
			encap seg6 mode encap.red segs fc00:0:0512:: dev veth2

	# SRv6 microSID Decap (for DEBUG only)
	ip netns exec $NODE ip -6 route add fc01:0:0512::/128 \
		encap seg6local action End.DX4 nh4 0.0.0.0 dev veth1
fi

# Forward Routing
ip netns exec $NODE ip -6 route add fc00:0::/32 via fd00:a1:b0::2 dev veth2

# ip6tables rule to mark ECT+CE traffic
ip netns exec $NODE ip6tables \
	-t mangle -A POSTROUTING -d fc00:0:512:: -j TOS --set-tos 0x03/0xff

set +e
read -r -d '' gw1_env <<-EOF
	mount -t bpf bpf "${BPFFS_PATH}"
	mount -t tracefs nodev /sys/kernel/tracing

	# It allows to load maps with many entries without failing
	ulimit -l unlimited

	mkdir "${BPFFS_PATH}"/{progs,maps}

	${BPFTOOL} prog loadall \
		"${OBJ_PATH}/xdp.bpf.o" /sys/fs/bpf/progs \
		pinmaps /sys/fs/bpf/maps \
		type xdp

	# required otherwise redirect (on the other peer) for veth won't work
	${BPFTOOL} net attach xdpdrv \
		pinned "${BPFFS_PATH}/progs/xdp_sr6decap" \
		dev veth2

	# decap SID (in bytes)
	# key:
	# 	0-15:	SID 				(fc01:0:0512::)
	# value:
	# 	0-3: table id (254)
	# 	4-7: reserved
	${BPFTOOL} \
		map update \
		pinned "${BPFFS_PATH}/maps/sr6decap_table"			\
	        key hex         fc 01 00 00 05 12 00 00 00 00 00 00 00 00 00 00 \
	        value hex       fe 00 00 00 00 00 00 00

	${BPFTOOL} net attach xdpdrv \
		pinned "${BPFFS_PATH}/progs/xdp_sr6encap" \
		dev veth1

	# encap policy (in bytes)
	# key:
	# 	0-3:	ipv4 dst address		(10.0.2.1)
	# value:
	# 	0-7:	ipv6 Source tunnel address	(fd00:a1:b0::1)
	# 	8-15:	ipv6 Destination uSID carrier	(fc00:0:0512::)
	${BPFTOOL} \
		map update \
		pinned "${BPFFS_PATH}/maps/sr6encap_ip4_table"			\
	        key hex         01 02 00 0a                                     \
	        value hex       fd 00 00 a1 00 b0 00 00 00 00 00 00 00 00 00 01 \
	                        fc 00 00 00 05 12 00 00 00 00 00 00 00 00 00 00

	/bin/bash
EOF
set -e


####################
#### Node: rt0 #####
####################
NODE=rt0
echo -e "\nNode: $NODE"
ip netns exec $NODE sysctl -w net.ipv6.conf.all.forwarding=1

ip netns exec $NODE ip link set dev lo up
ip netns exec $NODE ip link set dev veth3 up
ip netns exec $NODE ip link set dev veth4 up
ip netns exec $NODE ip addr add fd00:a1:b0::2/48 dev veth3
ip netns exec $NODE ip addr add fd00:b0:a2::1/48 dev veth4

if [ "$DEBUG" == "on" ]; then
	# Actually do nothing.
	:
fi

# Forward Routing
ip netns exec $NODE ip -6 route add fc00:0::/32 via fd00:b0:a2::2 dev veth4

# Reverse Routing
ip netns exec $NODE ip -6 route add fc01:0::/32 via fd00:a1:b0::1 dev veth3

set +e
read -r -d '' rt0_env <<-EOF
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
		dev veth3

	${BPFTOOL} net attach xdpdrv \
		pinned "${BPFFS_PATH}/progs/xdp_pass" \
		dev veth4

	/bin/bash
EOF
set -e


####################
#### Node: gw2 #####
####################
NODE=gw2
echo -e "\nNode: $NODE"
ip netns exec $NODE sysctl -w net.ipv4.conf.all.forwarding=1
ip netns exec $NODE sysctl -w net.ipv6.conf.all.forwarding=1
# disable also rp_filter on the receiving decap interface that will forward the
# packet to the right destination (through the nexthop)
ip netns exec $NODE sysctl -w net.ipv4.conf.all.rp_filter=0
ip netns exec $NODE sysctl -w net.ipv4.conf.lo.rp_filter=0
ip netns exec $NODE sysctl -w net.ipv4.conf.default.rp_filter=0
ip netns exec $NODE sysctl -w net.ipv4.conf.veth5.rp_filter=0
ip netns exec $NODE sysctl -w net.ipv4.conf.veth6.rp_filter=0

ip netns exec $NODE ip link set dev lo up
ip netns exec $NODE ip link set dev veth5 up
ip netns exec $NODE ip link set dev veth6 up
ip netns exec $NODE ip addr add fd00:b0:a2::2/48 dev veth5
ip netns exec $NODE ip addr add 10.0.2.254/24 dev veth6

if [ "$DEBUG" == "on" ]; then
	# SRv6 microSID Encap (for DEBUG only)
	ip netns exec $NODE ip -4 route add 10.0.1.1/32 \
			encap seg6 mode encap.red segs fc01:0:0512:: dev veth6

	# SRv6 microSID Decap (for DEBUG only)
	ip netns exec $NODE ip -6 route add fc00:0:0512::/128 \
		encap seg6local action End.DX4 nh4 0.0.0.0 dev veth5
fi

# Reverse Routing
ip netns exec $NODE ip -6 route add fc01:0::/32 via fd00:b0:a2::1 dev veth5

set +e
read -r -d '' gw2_env <<-EOF
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
		pinned "${BPFFS_PATH}/progs/xdp_sr6decap" \
		dev veth5

	# decap SID (in bytes)
	# key:
	# 	0-15:	SID 				(fc00:0:0512::)
	# value:
	# 	0-3: table id (254)
	# 	4-7: reserved
	${BPFTOOL} \
		map update \
		pinned "${BPFFS_PATH}/maps/sr6decap_table"			\
	        key hex         fc 00 00 00 05 12 00 00 00 00 00 00 00 00 00 00 \
	        value hex       fe 00 00 00 00 00 00 00

	${BPFTOOL} net attach xdpdrv \
		pinned "${BPFFS_PATH}/progs/xdp_sr6encap" \
		dev veth6

	# encap policy (in bytes)
	# key:
	# 	0-3:	ipv4 dst address		(10.0.1.1)
	# value:
	# 	0-15:	ipv6 Source tunnel address	(fd00:b0:a2::2)
	# 	16-31:	ipv6 Destination uSID carrier	(fc01:0:0512::)
	${BPFTOOL} \
		map update \
		pinned "${BPFFS_PATH}/maps/sr6encap_ip4_table"			\
	        key hex         01 01 00 0a                                     \
	        value hex       fd 00 00 b0 00 a2 00 00 00 00 00 00 00 00 00 02 \
	                        fc 01 00 00 05 12 00 00 00 00 00 00 00 00 00 00

	/bin/bash
EOF
set -e


###################
#### Node: h1 #####
###################
NODE=h1
echo -e "\nNode: $NODE"
ip netns exec $NODE ip link set dev lo up
ip netns exec $NODE ip link set dev veth7 up
ip netns exec $NODE ip addr add 10.0.2.1/24 dev veth7
ip netns exec $NODE ip -4 route add 10.0.1.0/24 via 10.0.2.254 dev veth7

set +e
read -r -d '' h1_env <<-EOF
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
		dev veth7

	/bin/bash
EOF
set -e


###############################
## Create a new tmux session ##
###############################
tmux new-session -d -s $TMUX -n h0 ip netns exec h0 bash -c "${h0_env}"
tmux new-window -t $TMUX -n gw1 ip netns exec gw1 bash -c "${gw1_env}"
tmux new-window -t $TMUX -n rt0 ip netns exec rt0 bash -c "${rt0_env}"
tmux new-window -t $TMUX -n gw2 ip netns exec gw2 bash -c "${gw2_env}"
tmux new-window -t $TMUX -n h1 ip netns exec h1 bash -c "${h1_env}"
tmux set-option -g mouse on
tmux select-window -t :0
tmux attach -t $TMUX
