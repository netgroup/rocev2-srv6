sudo tc qdisc del dev veth-gw1-rt1 root 2>/dev/null
sudo tc qdisc del dev veth-gw1-rt2 root 2>/dev/null
# Ritardo + strozzatura (accumulo)
sudo tc qdisc add dev veth-gw1-rt1 root handle 1: netem delay 300ms
sudo tc qdisc add dev veth-gw1-rt1 parent 1:1 handle 10: pfifo limit 2

sudo tc qdisc add dev veth-gw1-rt2 root handle 1: netem delay 300ms
sudo tc qdisc add dev veth-gw1-rt2 parent 1:1 handle 10: pfifo limit 2

