#!/bin/bash

readonly BPFTOOL="bpftool"
readonly OBJ="./.output/xdp.bpf.o"
readonly BPFFS_PATH="/sys/fs/bpf"
readonly HELPER_PROG="./xdp_network/devmap_set"

if ! command -v "${BPFTOOL}" &>/dev/null; then
    echo "bpftool program is not available"
    exit 1
fi

SND_IF_NAME=ens11np0
RCV_IF_NAME=ens9np1
SND_ID=$(< /sys/class/net/$SND_IF_NAME/ifindex)
RCV_ID=$(< /sys/class/net/$RCV_IF_NAME/ifindex)

ulimit -l unlimited

mkdir "${BPFFS_PATH}"/{progs,maps}

bpftool prog loadall \
	"${OBJ}" /sys/fs/bpf/progs \
	pinmaps /sys/fs/bpf/maps 

MAP_DEVMAP=$(bpftool map | awk '/tx_devmap/ {sub(":","",$1); print $1}')
ID_ENCAP=$(bpftool prog show | awk '/xdp_sr6encap/ {print $1}' | cut -d: -f1)
ID_DECAP=$(bpftool prog show | awk '/xdp_sr6decap/ {print $1}' | cut -d: -f1)
ID_RATE=$(bpftool prog | awk '/xdp_rate_then_forward/ {sub(":","",$1); print $1}')
ID_DISP=$(bpftool prog | awk '/xdp_dispatch/ {sub(":","",$1); print $1}')

# Configure  devmap with helper program
$HELPER_PROG --map-id $MAP_DEVMAP --key 0 --if $RCV_IF_NAME \
    --prog-pinned /sys/fs/bpf/progs/xdp_sr6decap
$HELPER_PROG --map-id $MAP_DEVMAP --key 1 --if $SND_IF_NAME \
    --prog-pinned /sys/fs/bpf/progs/xdp_sr6decap

# Create the tailcall pipeline
sudo bpftool map update pinned /sys/fs/bpf/maps/c_prog_array key 0 0 0 0 value id $ID_ENCAP
sudo bpftool map update pinned /sys/fs/bpf/maps/c_prog_array key 1 0 0 0 value id $ID_DECAP
sudo bpftool map update pinned /sys/fs/bpf/maps/c_prog_array key 2 0 0 0 value id $ID_RATE

###################
###### SENDER #####
###################

${BPFTOOL} net attach xdpdrv \
	pinned "${BPFFS_PATH}/progs/xdp_dispatch" \
	dev ${SND_IF_NAME}


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
					fc f0 00 00 00 a2 00 d4 00 00 00 00 00 00 00 00

${BPFTOOL} \
	map update \
	pinned "${BPFFS_PATH}/maps/sr6decap_table"			\
	key hex         fc f0 00 00 00 a1 00 d4 00 00 00 00 00 00 00 00 \
	value hex       64 00 00 00 \
					00 00 00 00

# for the routing without looking at the kernel fib 
${BPFTOOL} \
	map update \
	pinned "${BPFFS_PATH}/maps/mac_fwd_map" \
	key hex			fc f0 00 00 00 a2 00 d4 00 00 00 00 00 00 00 00 \
	value hex		b8 ce f6 1b 4d 5d \
					b8 ce f6 1b 4c c1 \
	           		04 00 00 00

${BPFTOOL} \
	map update pinned /sys/fs/bpf/maps/mac_fwd_v4_map \
    key hex 	01 02 37 0a \
    value hex 	b8 ce f6 1b 4d 5d \
				b8 ce f6 1b 4c c1 \
	           	04 00 00 00



 

###################
##### RECEIVER ####
###################

${BPFTOOL} net attach xdpdrv \
	pinned "${BPFFS_PATH}/progs/xdp_dispatch" \
	dev ${RCV_IF_NAME}


# encap policy (in bytes)
# key:
#       0-3:    ipv4 dst address                (10.0.2.1)
# value:
#       0-7:    ipv6 Source tunnel address      (fd00:a1:b0::1)
#       8-15:   ipv6 Destination uSID carrier   (fc00:0:0512::)
${BPFTOOL} \
        map update \
        pinned "${BPFFS_PATH}/maps/sr6encap_ip4_table"                  \
        key hex         01 01 37 0a                                     \
        value hex       fd 00 00 a1 00 b0 00 00 00 00 00 00 00 00 00 01 \
                        fc f0 00 00 00 a1 00 d4 00 00 00 00 00 00 00 00

# decap SID (in bytes)
# key:
#       0-15:   SID                             (fc01:0:0512::)
# value:
#       0-3: table id (100)
#       4-7: reserved
${BPFTOOL} \
        map update \
        pinned "${BPFFS_PATH}/maps/sr6decap_table"                      \
        key hex         fc f0 00 00 00 a2 00 d4 00 00 00 00 00 00 00 00 \
        value hex       64 00 00 00 \
                        00 00 00 00

# for the routing without looking at the kernel fib
${BPFTOOL} \
	map update \
	pinned "${BPFFS_PATH}/maps/mac_fwd_map" \
	key hex				fc f0 00 00 00 a1 00 d4 00 00 00 00 00 00 00 00 \
	value hex			b8 ce f6 1b 4d 5c \
						b8 ce f6 1b 4c c0 \
						05 00 00 00



${BPFTOOL} \
	map update pinned /sys/fs/bpf/maps/mac_fwd_v4_map \
    key hex 	01 01 37 0a \
    value hex 	b8 ce f6 1b 4d 5c \
	        	b8 ce f6 1b 4c c0 \
			  	05 00 00 00


#!/bin/bash
