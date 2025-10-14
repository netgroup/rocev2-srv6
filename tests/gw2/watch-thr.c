#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <time.h>

#define MAP_ID_QP_THROUGHPUT 26  // <-- sostituisci con il tuo map id
#define POLL_INTERVAL_MS 10

struct qp_stats {
    __u64 bytes;
    __u64 start_ns;
    __u64 last_ns;
    __u64 last_bps;
    __u64 below_ns_accum;
};

struct entry {
    __u32 qp;
    struct qp_stats st;
};

static unsigned long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ts.tv_sec * 1000ULL + ts.tv_nsec / 1000000ULL;
}

int cmp_qp(const void *a, const void *b) {
    const struct entry *ea = a, *eb = b;
    return (ea->qp > eb->qp) - (ea->qp < eb->qp);
}

int main(void) {
    int map_fd = bpf_map_get_fd_by_id(MAP_ID_QP_THROUGHPUT);
    if (map_fd < 0) {
        perror("bpf_map_get_fd_by_id");
        return 1;
    }

    FILE *csv = fopen("throughput.csv", "w");
    if (!csv) {
        perror("fopen");
        return 1;
    }

    fprintf(csv, "timestamp_ms,qp_id,bytes,start_ns,last_ns,last_bps,below_ns_accum\n");
    fflush(csv);

    while (1) {
        __u32 key, next_key;
        struct qp_stats st;
        struct entry entries[1024];
        int n = 0;

        // iterazione mappa
        if (bpf_map_get_next_key(map_fd, NULL, &key) == 0) {
            do {
                if (bpf_map_lookup_elem(map_fd, &key, &st) == 0) {
                    entries[n].qp = key;   // QPN puro
                    entries[n].st = st;
                    n++;
                }
            } while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0 && (key = next_key, 1));
        }

        // ordina per qp_id crescente
        qsort(entries, n, sizeof(struct entry), cmp_qp);

        unsigned long long ts_ms = now_ms();
        for (int i = 0; i < n; i++) {
            fprintf(csv, "%llu,0x%x,%llu,%llu,%llu,%llu,%llu\n",
                    ts_ms,
                    entries[i].qp,
                    entries[i].st.bytes,
                    entries[i].st.start_ns,
                    entries[i].st.last_ns,
                    entries[i].st.last_bps,
                    entries[i].st.below_ns_accum);
        }

        fflush(csv);
        usleep(POLL_INTERVAL_MS * 1000);
    }

    fclose(csv);
    close(map_fd);
    return 0;
}

