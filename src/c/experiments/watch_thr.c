#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdint.h>

#define MAP_PIN_PATH "/sys/fs/bpf/qp_throughput"  // pin with bpftool
#define POLL_INTERVAL_MS 100

struct qp_stats {
    __u64 bytes;
    __u64 start_ns;
    __u64 last_ns;
    __u64 last_bps;
    __u64 below_ns_accum;
};

static unsigned long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ts.tv_sec * 1000ULL + ts.tv_nsec / 1000000ULL;
}

int main(void) {
    int map_fd = bpf_obj_get(MAP_PIN_PATH);
    if (map_fd < 0) {
        perror("bpf_obj_get qp_throughput (check pin path)");
        return 1;
    }

    FILE *csv = fopen("throughput.csv", "w");
    if (!csv) {
        perror("fopen csv");
        close(map_fd);
        return 1;
    }
    fprintf(csv, "timestamp_ms,qp_id,bytes,start_ns,last_ns,last_bps,below_ns_accum\n");
    fflush(csv);

    while (1) {
        unsigned long long ts_ms = now_ms();

        __be32 prev_key;
        __be32 cur_key;
        int have_prev = 0;

        // Iterate: pass NULL for first key, then keep advancing using the last key returned.
        while (1) {
            int ret = bpf_map_get_next_key(map_fd, have_prev ? &prev_key : NULL, &cur_key);
            if (ret != 0) {
                // No more keys (ENOENT) or transient error; end this scan.
                break;
            }

            struct qp_stats stats;
            if (bpf_map_lookup_elem(map_fd, &cur_key, &stats) == 0) {
                fprintf(csv, "%llu,%u,%llu,%llu,%llu,%llu,%llu\n",
                        ts_ms,
                        ntohl(cur_key),
                        stats.bytes,
                        stats.start_ns,
                        stats.last_ns,
                        stats.last_bps,
                        stats.below_ns_accum);
            }
            prev_key = cur_key;
            have_prev = 1;
        }

        fflush(csv);
        usleep(POLL_INTERVAL_MS * 1000);
    }

    // not reached
    fclose(csv);
    close(map_fd);
    return 0;
}

