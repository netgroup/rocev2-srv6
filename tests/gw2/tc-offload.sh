#!/bin/bash
set -e

IFACE="ens10np1"

# Abilita hw offload
ethtool -K $IFACE hw-tc-offload on

# Aggiungi (o sostituisci) la qdisc clsact
tc qdisc replace dev $IFACE clsact

# Filtro flower in ingress: droppa TCP/22 in HW (skip_sw = solo HW)
tc filter add dev $IFACE egress protocol ip prio 1 \
    flower ip_proto tcp dst_port 22 skip_sw \
    action drop

# Mostra i filtri per verificare se è 'in_hw'
tc -s filter show dev $IFACE egress


 

