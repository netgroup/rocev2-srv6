ip l set ens10np1 xdp off
ip l set veth-gw2-rt1 xdp off
ip l set veth-gw2-rt2 xdp off

umount /sys/fs/bpf
