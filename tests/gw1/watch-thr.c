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

#define MAP_ID_QP_THROUGHPUT 12   // aggiorna con il tuo id
#define POLL_INTERVAL_MS 100      // ogni 100ms

// Struttura coerente con il programma eBPF
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
    int map_fd = bpf_map_get_fd_by_id(MAP_ID_QP_THROUGHPUT);
    if (map_fd < 0) {
        perror("bpf_map_get_fd_by_id qp_throughput");
        return 1;
    }

    FILE *csv = fopen("throughput.csv", "w");
    if (!csv) {
        perror("fopen csv");
        return 1;
    }

    fprintf(csv, "timestamp_ms,qp_id,bytes,start_ns,last_ns,last_bps,below_ns_accum\n");
    fflush(csv);

    while (1) {
        __be32 key, next_key;
        int ret;

        unsigned long long ts_ms = now_ms();

        // inizia dal primo elemento
        ret = bpf_map_get_next_key(map_fd, NULL, &key);
        while (ret == 0) {
            struct qp_stats stats;
            if (bpf_map_lookup_elem(map_fd, &key, &stats) == 0) {
                fprintf(csv, "%llu,%u,%llu,%llu,%llu,%llu,%llu\n",
                        ts_ms,
                        ntohl(key),
                        stats.bytes,
                        stats.start_ns,
                        stats.last_ns,
                        stats.last_bps,
                        stats.below_ns_accum);
            }
            // passa alla chiave successiva
            ret = bpf_map_get_next_key(map_fd, &key, &next_key);
            key = next_key;
        }

        fflush(csv);
        usleep(POLL_INTERVAL_MS * 1000);
    }

    fclose(csv);
    close(map_fd);
    return 0;
}

