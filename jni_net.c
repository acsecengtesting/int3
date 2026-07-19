// SPDX-License-Identifier: GPL-2.0
// Userspace loader for JNI exploit network detector (kernel-side VMA approach)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define MAX_STACK_DEPTH 16
#define MAX_FILENAME 64

struct jni_connect_event {
    __u32 pid;
    __u32 tid;
    __u64 timestamp;
    __u64 mnt_ns_inum;
    __u32 dest_addr;
    __u16 dest_port;
    __u16 stack_depth;
    __u64 user_stack[MAX_STACK_DEPTH];
    char  suspicious_lib[MAX_FILENAME];
    char  comm[16];
};

static volatile int running = 1;

static void sig_handler(int sig) {
    running = 0;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct jni_connect_event *e = data;

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    char time_buf[32];
    struct tm *tm = localtime(&ts.tv_sec);
    strftime(time_buf, sizeof(time_buf), "%H:%M:%S", tm);

    char addr_buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &e->dest_addr, addr_buf, sizeof(addr_buf));
    __u16 port = ntohs(e->dest_port);

    printf("[%s] ALERT: Non-networking native lib on connect() stack!\n", time_buf);
    printf("       pid=%d comm=%s mnt_ns=%llu\n",
           e->pid, e->comm, (unsigned long long)e->mnt_ns_inum);
    printf("       dest=%s:%d\n", addr_buf, port);
    printf("       suspicious_lib=%s\n", e->suspicious_lib);
    printf("       stack:\n");
    for (int i = 0; i < e->stack_depth && i < MAX_STACK_DEPTH; i++) {
        if (e->user_stack[i])
            printf("         [%d] 0x%llx\n", i, (unsigned long long)e->user_stack[i]);
    }
    printf("\n");
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

    printf("JNI exploit network detector (kernel-side VMA resolution)\n\n");

    obj = bpf_object__open_file("jni_net.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object failed\n");
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: loading BPF object failed: %d\n", err);
        goto cleanup;
    }

    prog = bpf_object__find_program_by_name(obj, "kprobe_tcp_connect");
    if (!prog) {
        fprintf(stderr, "ERROR: finding kprobe program failed\n");
        err = 1;
        goto cleanup;
    }

    link = bpf_program__attach(prog);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "ERROR: attaching kprobe:tcp_connect failed\n");
        link = NULL;
        err = 1;
        goto cleanup;
    }

    printf("Attached kprobe:tcp_connect with user-stack VMA inspection.\n");
    printf("Alerting when connect() stack contains non-networking .so files.\n");
    printf("Press Ctrl+C to stop.\n\n");

    int map_fd = bpf_object__find_map_fd_by_name(obj, "jni_net_events");
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
