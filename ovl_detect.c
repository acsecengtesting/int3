// SPDX-License-Identifier: GPL-2.0
// Userspace loader for overlay writable-layer file detection
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define MAX_FILENAME 128
#define MAX_PATH_COMPONENT 64

#define FILE_TYPE_SO    1
#define FILE_TYPE_CLASS 2
#define FILE_TYPE_JAR   3

struct ovl_alert_event {
    __u32 pid;
    __u32 tid;
    __u64 timestamp;
    __u64 mnt_ns_inum;
    __u8  file_type;
    char  filename[MAX_FILENAME];
    char  parent_dir[MAX_PATH_COMPONENT];
    char  comm[16];
};

static volatile int running = 1;

static void sig_handler(int sig) {
    running = 0;
}

static __u64 get_host_mnt_ns(void) {
    struct stat st;
    if (stat("/proc/1/ns/mnt", &st) == 0)
        return st.st_ino;
    return 0;
}

static const char *file_type_str(__u8 ft) {
    switch (ft) {
        case FILE_TYPE_SO: return ".so";
        case FILE_TYPE_CLASS: return ".class";
        case FILE_TYPE_JAR: return ".jar";
        default: return "unknown";
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct ovl_alert_event *e = data;

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    char time_buf[32];
    struct tm *tm = localtime(&ts.tv_sec);
    strftime(time_buf, sizeof(time_buf), "%H:%M:%S", tm);

    printf("[%s] ALERT: %s from WRITABLE layer in container\n",
           time_buf, file_type_str(e->file_type));
    printf("       pid=%d comm=%s mnt_ns=%llu\n",
           e->pid, e->comm, (unsigned long long)e->mnt_ns_inum);
    printf("       file=%s/%s\n\n", e->parent_dir, e->filename);
    fflush(stdout);
    return 0;
}

int main(int argc, char **argv) {
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_link *link = NULL;
    struct ring_buffer *rb = NULL;
    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    __u64 host_ns = get_host_mnt_ns();
    if (!host_ns) {
        fprintf(stderr, "ERROR: could not read host mount namespace\n");
        return 1;
    }
    printf("Host mount namespace: %llu\n", (unsigned long long)host_ns);

    obj = bpf_object__open_file("ovl_detect.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object failed\n");
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: loading BPF object failed: %d\n", err);
        goto cleanup;
    }

    // Set host mount namespace in map
    int ns_map_fd = bpf_object__find_map_fd_by_name(obj, "host_mnt_ns");
    if (ns_map_fd >= 0) {
        __u32 key = 0;
        bpf_map_update_elem(ns_map_fd, &key, &host_ns, 0);
    }

    // Attach kprobe to ovl_open
    prog = bpf_object__find_program_by_name(obj, "kprobe_ovl_open");
    if (!prog) {
        fprintf(stderr, "ERROR: finding kprobe program failed\n");
        err = 1;
        goto cleanup;
    }

    link = bpf_program__attach(prog);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "ERROR: attaching kprobe:ovl_open failed\n");
        link = NULL;
        err = 1;
        goto cleanup;
    }

    printf("Container writable-layer detector attached (kprobe:ovl_open)\n");
    printf("Monitoring .so / .class / .jar from writable overlay layers...\n");
    printf("Press Ctrl+C to stop.\n\n");

    int map_fd = bpf_object__find_map_fd_by_name(obj, "ovl_events");
    if (map_fd < 0) {
        fprintf(stderr, "ERROR: finding events map failed\n");
        err = 1;
        goto cleanup;
    }

    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (libbpf_get_error(rb)) {
        fprintf(stderr, "ERROR: creating ring buffer failed\n");
        err = 1;
        goto cleanup;
    }

    while (running) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "ERROR: polling ring buffer: %d\n", err);
            break;
        }
    }

    printf("\nDetaching...\n");

cleanup:
    if (rb)
        ring_buffer__free(rb);
    if (link)
        bpf_link__destroy(link);
    if (obj)
        bpf_object__close(obj);

    return err != 0;
}
