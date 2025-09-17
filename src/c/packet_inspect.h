#define TIME_INTERVAL 49000 //nanoseconds
#define ETH_P_IP		0x0800 /* Internet Protocol v4 */
#define ETH_P_IPV6		0x86dd /* Internet Protocol v6 */
#define ETH_P_8021Q		0x8100	/* 802.1Q VLAN Extended Header  */
#define ETH_P_8021AD		0x88A8	/* 802.1ad Service VLAN */

// Define structure to store CNP count and last timestamp
struct cnp_data {
    __u64 count;      // CNP packet counter
    __u64 last_time;  // Timestamp of last received CNP (nanoseconds)
};

// BPF map to store CNP tracking data
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct cnp_data);
} cnp_counter SEC(".maps");


int packet_inspect(struct xdp_md *xdp) {
    void *data_end = (void *)(long)xdp->data_end;
    void *data = (void *)(long)xdp->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 eth_type = bpf_ntohs(eth->h_proto);
    void *ip_header = eth + 1;
    struct iphdr *ip4 = NULL;
    struct ipv6hdr *ip6 = NULL;
    struct udphdr *udp = NULL;
    void *udp_payload = NULL;

    if (eth_type == ETH_P_IP) {
        ip4 = ip_header;
        if ((void *)(ip4 + 1) > data_end)
            return XDP_PASS;

        if (ip4->protocol != IPPROTO_UDP)
            return XDP_PASS;

        udp = (struct udphdr *)(ip4 + 1);
    } else if(eth_type==ETH_P_IPV6){
	     ip6 = ip_header;
        if ((void *)(ip6 + 1) > data_end)
            return XDP_PASS;

        if (ip6->nexthdr != IPPROTO_UDP)
            return XDP_PASS;

        udp = (struct udphdr *)(ip6 + 1);
    	
    }else {
        return XDP_PASS;
    }

    if ((void *)(udp + 1) > data_end){
	    return XDP_PASS;}
   
    // Get UDP payload (RoCEv2 BTH starts here)
    udp_payload = (void *)(udp + 1);
    if ((void *)(udp_payload + 1) > data_end){

	    return XDP_PASS;}

    __u8 opcode = *((__u8 *)udp_payload); // First byte of BTH
   
    if (opcode == 0x81){ // Check if it's a CNP packet
        //bpf_printk("Detected RoCE CNP Packet (Opcode 0x81)\n");

        __u64 now_ns = bpf_ktime_get_ns(); // Get current timestamp
        __u32 key = 0;

        // Lookup map entry
        struct cnp_data *entry = bpf_map_lookup_elem(&cnp_counter, &key);

        if (entry) {
            __sync_fetch_and_add(&entry->count, 1); // Increment counter
             /*if( entry->count==3){

	    	if(now_ns - entry->last_time <=TIME_INTERVAL){

		
	   
		    	pr_debug("Change route!");
		}
	    		//reset counter
	       		struct cnp_data new_entry = {
                    		.count = 0,
                    		.last_time = now_ns
                	};
                	bpf_map_update_elem(&cnp_counter, &key, &new_entry, BPF_ANY);
		
            
		return XDP_PASS;
	    }*/
	    entry->last_time = now_ns;  // Update timestamp
            
	    bpf_printk("CNP count: %llu, Last timestamp: %llu ns\n", entry->count, entry->last_time);
        } else {
            // Initialize entry if it doesn't exist
            struct cnp_data new_entry = {
                .count = 1,
                .last_time = now_ns
            };
            bpf_map_update_elem(&cnp_counter, &key, &new_entry, BPF_ANY);
          //  bpf_printk("First CNP received. Initialized counter: 1, Timestamp: %llu ns\n", now_ns);
        }
    }

    return XDP_PASS;
}



