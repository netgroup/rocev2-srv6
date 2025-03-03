# Build the Podman Container for developing

In the `podman` folder, there is a README that details how to build the container for development purposes and for testing the eBPF/XDP programs.

# XDP/eBPF Programs

The `src/c` folder contains the `xdp.bpf.c` file, which includes three different XDP programs:

1. **sr6_encap**:  
   This program implements the SRv6 H.Encaps.Red. Currently, only encapsulation with one SID is supported, and the SRH is not used in any case. This program is intended to be attached to a network device receiving IPv4 traffic. Upon receiving IPv4 traffic, the program checks for the IPv4 Destination Address (DA) in the eBPF map called `sr6encap_ip4_table`. This map uses the IPv4 DA as the key, with the value consisting of the IPv6 Source Address for the tunnel and the SID (composed of several micro SIDs) to be included in the outer IPv6 Destination Address (DA).  
   For information on how this program is used, please refer to `tests/encap_decap_vrf_test.sh`.

2. **sr6_decap**:  
   This program implements the SRv6 End.DT4 behavior. It decapsulates inner IPv4 traffic by matching the outer IPv6 DA with the decap SID in the eBPF `sr6decap_table` map. If the IPv6 DA matches an entry in that map, the program retrieves the table used for performing the routing lookup of the decapsulated IPv4 packet.
  For information on how this program is used, please refer to `tests/encap_decap_vrf_test.sh`.

3. **xdp_pass**:  
   A dummy program that can be attached to veth pairs, enabling the redirect XDP helper functions to work.

# Tests

A testbed simulating a (small) virtual data center network is available in the `tests` folder. Specifically, the `encap_decap_vrf_tests.sh` script creates a virtual network composed of several network namespaces connected with veth pairs. To run the test, execute the script and ping from `h0` to `h1` using the following command:  
```bash
# ping 10.0.2.1
```
The command should succeed, with packets encapsulated on `gw1`, routed on `rt0`, and decapsulated on `gw2`, which then sends plain IPv4 traffic to the `h1` destination.
