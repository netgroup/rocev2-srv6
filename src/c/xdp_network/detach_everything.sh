bpftool net detach xdp dev ens9np1

sleep 1

bpftool net detach xdp dev ens11np0

sleep 1

rm -rf /sys/fs/bpf/*