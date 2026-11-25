// Inspect only maps held by the selected TC program. One line per counter:
// family outcome prog_id map_id value_cpu0 value_cpu1 ...
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int read_program(__u32 id) {
    int prog_fd = bpf_prog_get_fd_by_id(id);
    if (prog_fd < 0) {
        perror("open TC program");
        return 1;
    }
    __u32 ids[64];
    struct bpf_prog_info prog = {
        .nr_map_ids = sizeof(ids) / sizeof(*ids),
        .map_ids = (__u64)(uintptr_t)ids,
    };
    __u32 len = sizeof(prog);
    if (bpf_prog_get_info_by_fd(prog_fd, &prog, &len) < 0) {
        perror("read TC program");
        return 1;
    }
    if (prog.nr_map_ids > sizeof(ids) / sizeof(*ids)) {
        fprintf(stderr, "unsupported program map count\n");
        return 1;
    }
    int family = 0;
    const char *names[] = {"SUBMITTED_EVENT", "DROPPED_PACKETS"};
    const char *outcomes[] = {"submitted", "ring_drop"};
    int counters[] = {-1, -1};
    __u32 map_ids[2] = {0};
    for (__u32 i = 0; i < prog.nr_map_ids; i++) {
        int fd = bpf_map_get_fd_by_id(ids[i]);
        struct bpf_map_info info = {0};
        len = sizeof(info);
        if (fd < 0 || bpf_map_get_info_by_fd(fd, &info, &len) < 0) {
            perror("read TC map info");
            return 1;
        }
        int v = !strcmp(info.name, "EVENTS_IPV4_0") ? 4 :
                !strcmp(info.name, "EVENTS_IPV6_0") ? 6 : 0;
        if (v) {
            if (family != 0 || info.type != BPF_MAP_TYPE_RINGBUF) {
                fprintf(stderr, "expected split TC ring layout\n");
                return 1;
            }
            family = v;
        }
        for (int k = 0; k < 2; k++) {
            if (!strcmp(info.name, names[k])) {
                if (counters[k] != -1 || info.type != BPF_MAP_TYPE_PERCPU_ARRAY ||
                    info.key_size != 4 || info.value_size != 8 || info.max_entries != 1) {
                    fprintf(stderr, "unsupported counter layout: %s\n", info.name);
                    return 1;
                }
                map_ids[k] = info.id;
                counters[k] = fd;
                fd = -1;
                break;
            }
        }
        if (fd >= 0)
            close(fd);
    }
    if (family) {
        int ncpu = libbpf_num_possible_cpus();
        if (ncpu < 1)
            return 1;
        uint64_t *values = calloc((size_t)ncpu, sizeof(*values));
        if (!values)
            return 1;
        __u32 key = 0;
        for (int k = 0; k < 2; k++) {
            if (bpf_map_lookup_elem(counters[k], &key, values) < 0) {
                perror("read per-CPU outcomes");
                return 1;
            }
            printf("%d %s %u %u", family, outcomes[k], id, map_ids[k]);
            for (int cpu = 0; cpu < ncpu; cpu++)
                printf(" %" PRIu64, values[cpu]);
            putchar('\n');
        }
        free(values);
    }
    for (int k = 0; k < 2; k++)
        if (counters[k] >= 0)
            close(counters[k]);
    close(prog_fd);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "expected TC program IDs\n");
        return 1;
    }
    for (int i = 1; i < argc; i++) {
        char *end;
        errno = 0;
        unsigned long id = strtoul(argv[i], &end, 10);
        if (errno || *end || id == 0 || id > UINT32_MAX || read_program((__u32)id))
            return 1;
    }
    return 0;
}
