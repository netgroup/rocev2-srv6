#!/usr/bin/env python3
import time
import subprocess
import os

# Namespace where the interface is visible.
GW2_NAMESPACE = "gw2"
GW1_NAMESPACE ="gw1"
# Global statistics: only track previous byte counts and computed Gbps.
stats = {
    'tx': {'Gbps': 0, 'bytes': 0},
    'rx': {'Gbps': 0, 'bytes': 0}
}

def lookup(ms):
    """
    Reads ethtool stats for interface ens9np0 on GW1 by executing the
    ethtool command inside the gw1 namespace. It then calculates the TX/RX rates in Gbps.
    """
    if ms%10==0:
            subprocess.call('clear')


            print("TX (Gbps) = {:12.3f}".format(stats['tx']['Gbps']))
            print("RX (Gbps) = {:12.3f}".format(stats['rx']['Gbps']))

    command = ["ethtool", "-S", "ens9np0"]
    try:
        raw = subprocess.check_output(command).decode('utf-8')
    except subprocess.CalledProcessError as e:
        print("Error reading ethtool stats:", e)
        return

    # Parse the ethtool output into a dictionary.
    stat_lines = {}
    for line in raw.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            try:
                stat_lines[key.strip()] = int(value.strip())
            except ValueError:
                continue

    # Use _phy keys if available, otherwise fall back.
    tx_bytes = stat_lines.get("tx_bytes_phy", stat_lines.get("tx_bytes", 0))
    rx_bytes = stat_lines.get("rx_bytes_phy", stat_lines.get("rx_bytes", 0))

    # Calculate TX rate (delta bytes * 8 / 1e9) for Gbps.
    tx_rate = (tx_bytes - stats['tx']['bytes']) * (8.0 / 0.1/1e9)
    stats['tx']['Gbps'] = tx_rate
    stats['tx']['bytes'] = tx_bytes

    # Similarly for RX.
    rx_rate = (rx_bytes - stats['rx']['bytes']) * (8.0 / 0.1/1e9)
    stats['rx']['Gbps'] = rx_rate
    stats['rx']['bytes'] = rx_bytes

#    print("TX (Gbps) = {:12.3f}".format(stats['tx']['Gbps']))
 #   print("RX (Gbps) = {:12.3f}".format(stats['rx']['Gbps']))

def update_encap_map(new_uSID_hex):
    """
    Updates the encapsulation map (/sys/fs/bpf/maps/sr6encap_ip4_table)
    with a new uSID carrier value.
    
    The map value is 32 bytes:
      - 16 bytes: fixed tunnel source (e.g., fd00:a1:b0::1)
      - 16 bytes: the new uSID carrier (provided as new_uSID_hex)
      
    The key (IPv4 destination) is hardcoded (here as "01 01 37 0a").
    """


    map_path = "/sys/fs/bpf/maps/sr6encap_ip4_table"
    if not os.path.exists(map_path):
        print("Encap map file {} does not exist.".format(map_path))
        return

    key_bytes = "01 02 37 0a".split()  # Represents IPv4 address
    # Fixed tunnel source (adjust as needed).
    tunnel_source = "fd 00 00 a1 00 b0 00 00 00 00 00 00 00 00 00 01".split()
    new_uSID_list = new_uSID_hex.split()
    value_bytes = tunnel_source + new_uSID_list
    command = ["bpftool", "map", "update", "pinned", map_path, "key", "hex"] + key_bytes + ["value", "hex"] + value_bytes

    subprocess.check_call(command)
    print("Updating encap map with new uSID carrier:")
    print("Command:", " ".join(command))
    try:
        subprocess.check_call(command)
    except subprocess.CalledProcessError as e:
        print("Error updating encap map:", e)
        exit(-1)


def main():
    RX_Gbps_THRESHOLD = 0.8  # 
    required_count = 5     # Require 2 consecutive seconds to trigger a change.

    # Define SID values for both maps for the two paths.
    # PRIMARY (Path over rt1):
    primary_encap_sid = "fc f0 00 00 00 b1 00 0e 00 a2 00 d4 00 00 00 00"
    secondary_encap_sid = "fc f0 00 00 00 b2 00 0e 00 a2 00 d4 00 00 00 00"

    
    current_path = "primary"
    # Update both maps initially with the primary SID values.
    update_encap_map(primary_encap_sid)
   # update_decap_map(primary_decap_sid)
    print("Initial path: PRIMARY (Path over rt1)")

    below_count = 0
    above_count = 0
    previous=1.0
    ms=0
    while True:
        ms+=1
       # subprocess.call('clear')
        lookup(ms)
        tx_gbps = stats['tx']['Gbps']
        rx_gbps=stats['rx']['Gbps'] 
       # print("Current TX Gbps on ens10np1 (GW2): {:.3f}".format(tx_gbps))
       # print("Current active path:", current_path.upper())
        
        if rx_gbps == 0:
            below_count = 0
            above_count = 0
                   
        else:
            
            if previous - rx_gbps > RX_Gbps_THRESHOLD:
                below_count += 1
                above_count = 0
        
                if below_count >= required_count and current_path != "secondary":
                    print("TX rate below threshold for {} seconds. Switching to SECONDARY path (via rt2).".format(required_count))
                    
                    update_encap_map(secondary_encap_sid)
                    current_path = "secondary"
                    below_count = 0
                    previous=stats['rx']['Gbps']
                    print("previous:    ",previous)
                elif below_count >= required_count and current_path != "primary":
                    print("TX rate below threshold for {} seconds. Switching to PRIMARY path (via rt1).".format(required_count))

                    update_encap_map(primary_encap_sid)
                    current_path="primary"
                    below_count=0
                    previous=stats['rx']['Gbps']

                else:
                    below_count+=1
            else:
                if(previous<rx_gbps):
                    previous=rx_gbps
                above_count += 1
                below_count = 0
        
        time.sleep(0.1)

if __name__ == '__main__':
    main()
    
