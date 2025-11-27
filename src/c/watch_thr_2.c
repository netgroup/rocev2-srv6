// gcc -O2 -Wall -o qp_csv qp_csv.c -lbpf
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

#include "uthash.h"  // https://troydhanson.github.io/uthash/

#define MAP_PIN_PATH "/sys/fs/bpf/qp_throughput"
#define POLL_INTERVAL_MS 100

struct qp_stats {
    __u64 bytes;
    __u64 start_ns;
    __u64 last_ns;
    __u64 last_bps;
    __u64 below_ns_accum;
} __attribute__((packed));

struct prev_entry {
    uint32_t qp_id;          // host order
    struct qp_stats stats;   // last snapshot
    int seen;                // mark seen in this scan
    UT_hash_handle hh;
};

static unsigned long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ts.tv_sec * 1000ULL + ts.tv_nsec / 1000000ULL;
}

static int stats_changed(const struct qp_stats *a, const struct qp_stats *b) {
    return memcmp(a, b, sizeof(*a)) != 0;
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

    struct prev_entry *prev_map = NULL;

    for (;;) {
        unsigned long long ts = now_ms();

        // mark all unseen before the scan
        for (struct prev_entry *e = prev_map; e; e = e->hh.next) e->seen = 0;

        __be32 prev_key_net;
        __be32 cur_key_net;
        int have_prev = 0;

        for (;;) {
            int ret = bpf_map_get_next_key(map_fd, have_prev ? &prev_key_net : NULL, &cur_key_net);
            if (ret != 0) {
                // end of keys (ENOENT) or transient error: stop this scan
                break;
            }

            struct qp_stats cur = {0};
            if (bpf_map_lookup_elem(map_fd, &cur_key_net, &cur) == 0) {
                uint32_t qp_id = ntohl(cur_key_net);

                struct prev_entry *e = NULL;
                HASH_FIND(hh, prev_map, &qp_id, sizeof(qp_id), e);
                if (!e) {
                    // new key: treat as changed and add
                    e = (struct prev_entry *)calloc(1, sizeof(*e));
                    if (!e) {
                        fprintf(stderr, "alloc failure\n");
                        goto next_key;
                    }
                    e->qp_id = qp_id;
                    e->stats = cur;
                    e->seen = 1;
                    HASH_ADD(hh, prev_map, qp_id, sizeof(e->qp_id), e);

                    fprintf(csv, "%llu,%u,%llu,%llu,%llu,%llu,%llu\n",
                            ts, e->qp_id,
                            (unsigned long long)cur.bytes,
                            (unsigned long long)cur.start_ns,
                            (unsigned long long)cur.last_ns,
                            (unsigned long long)cur.last_bps,
                            (unsigned long long)cur.below_ns_accum);
                } else {
                    // existing: compare and update if changed
                    if (stats_changed(&cur, &e->stats)) {
                        fprintf(csv, "%llu,%u,%llu,%llu,%llu,%llu,%llu\n",
                                ts, e->qp_id,
                                (unsigned long long)cur.bytes,
                                (unsigned long long)cur.start_ns,
                                (unsigned long long)cur.last_ns,
                                (unsigned long long)cur.last_bps,
                                (unsigned long long)cur.below_ns_accum);
                        e->stats = cur;
                    }
                    e->seen = 1;
                }
            }
        next_key:
            prev_key_net = cur_key_net;
            have_prev = 1;
        }

        fflush(csv);

        // remove entries that disappeared from the map
        struct prev_entry *e, *tmp;
        HASH_ITER(hh, prev_map, e, tmp) {
            if (!e->seen) {
                HASH_DEL(prev_map, e);
                free(e);
            }
        }

        usleep(POLL_INTERVAL_MS * 1000);
    }

    // not reached
    fclose(csv);
    close(map_fd);
    return 0;
}

