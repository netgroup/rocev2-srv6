#!/bin/bash
set -e

# === Configurazione ===
BPFTOOL="bpftool"
OBJ_PATH="../../src/c/.output"
BPFFS="/sys/fs/bpf"
DEV="ens11np0"
IFINDEX=7

MAC_SRC="02:aa:bb:cc:11:00"   # gw1
MAC_DST="02:aa:bb:cc:22:00"   # gw2

SID_PRIMARY="fc f0 00 00 00 b1 00 0e 00 a2 00 d4 00 00 00 00"
SID_SECONDARY="fc f0 00 00 00 b2 00 0e 00 a2 00 d4 00 00 00 00"

# === Setup ===
mount -t bpf bpf $BPFFS 2>/dev/null || true
mkdir -p $BPFFS/{progs,maps}

ulimit -l unlimited

echo "[gw1] loading xdp_sr6encap on $DEV"
$BPFTOOL prog loadall "$OBJ_PATH/xdp.bpf.o" "$BPFFS/progs" \
    pinmaps "$BPFFS/maps" type xdp

$BPFTOOL net detach xdp dev $DEV 2>/dev/null || true
$BPFTOOL net attach xdpdrv pinned "$BPFFS/progs/xdp_sr6encap" dev $DEV

echo "[gw1] populating route_map"
# Entry primaria
$BPFTOOL map update pinned $BPFFS/maps/xdp_route_map \
    key hex $SID_PRIMARY \
    value hex \
      $(printf "%08x" $IFINDEX | sed 's/../& /g') \
      $(echo $MAC_SRC | sed 's/:/ /g') \
      $(echo $MAC_DST | sed 's/:/ /g')

# Entry secondaria
$BPFTOOL map update pinned $BPFFS/maps/xdp_route_map \
    key hex $SID_SECONDARY \
    value hex \
      $(printf "%08x" $IFINDEX | sed 's/../& /g') \
      $(echo $MAC_SRC | sed 's/:/ /g') \
      $(echo $MAC_DST | sed 's/:/ /g')

echo "[gw1] route_map configured (to gw2)"

