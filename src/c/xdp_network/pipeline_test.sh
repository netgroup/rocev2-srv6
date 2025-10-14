IFA=$(< /sys/class/net/ens11np0/ifindex)
IFB=$(< /sys/class/net/ens9np1/ifindex)

IFA_NAME=ens11np0
IFB_NAME=ens9np1


# Dispatcher
sudo bpftool prog loadall xdp_tail_pipeline.o /sys/fs/bpf/

ID_ENCAP=$(bpftool prog show | awk '/xdp_encap/ {print $1}' | cut -d: -f1)
ID_DECAP=$(bpftool prog show | awk '/xdp_decap/ {print $1}' | cut -d: -f1)
ID_RATE=$(bpftool prog | awk '/xdp_rate_then_forward/ {sub(":","",$1); print $1}')
ID_DISP=$(bpftool prog | awk '/xdp_dispatch/ {sub(":","",$1); print $1}')

MAP_PROGARR=$(bpftool map | awk '/c_prog_array/ {sub(":","",$1); print $1}')
MAP_DEVMAP=$(bpftool map | awk '/tx_devmap/ {sub(":","",$1); print $1}')
MAP_TB=$(bpftool map | awk '/tb_map/ {sub(":","",$1); print $1}')

# Pin maps
sudo bpftool map pin id $MAP_PROGARR /sys/fs/bpf/c_prog_array
sudo bpftool map pin id $MAP_DEVMAP /sys/fs/bpf/tx_devmap
sudo bpftool map pin id $MAP_TB /sys/fs/bpf/tb_map

# Configure maps
./devmap_set --map-id $MAP_DEVMAP --key 0 --if $IFB_NAME \
    --prog-pinned /sys/fs/bpf/xdp_decap
./devmap_set --map-id $MAP_DEVMAP --key 1 --if $IFA_NAME \
    --prog-pinned /sys/fs/bpf/xdp_decap

sudo bpftool map update pinned /sys/fs/bpf/c_prog_array key 0 0 0 0 value id $ID_ENCAP
sudo bpftool map update pinned /sys/fs/bpf/c_prog_array key 1 0 0 0 value id $ID_DECAP
sudo bpftool map update pinned /sys/fs/bpf/c_prog_array key 2 0 0 0 value id $ID_RATE

sudo bpftool net attach xdp id $ID_DISP dev $IFA_NAME
sudo bpftool net attach xdp id $ID_DISP dev $IFB_NAME


# Configure token bucket

# Assuming value is four u64 fields: tokens, last_refill_ns, rate_tokens_per_ns, burst_tokens
TOKENS=0
LAST=0
RATE=53687091         # ≈100 Mbit/s in fixed-point (0.0125×2³²)
BURST=$((1024*1024))  # 1 MB burst

sudo bpftool map update pinned /sys/fs/bpf/tb_map \
  key 0 0 0 0 \
  value hex \
    00 00 00 00 00 00 00 00 \
    00 00 00 00 00 00 00 00 \
    33 33 33 03 00 00 00 00 \
    00 00 10 00 00 00 00 00

