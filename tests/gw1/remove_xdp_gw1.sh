#ip l set ens9np0 xdp off
ip l set veth-gw1-rt1 xdp off
ip l set veth-gw1-rt2 xdp off

umount /sys/fs/bpf
