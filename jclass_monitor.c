// SPDX-License-Identifier: GPL-2.0
// Userspace loader for eBPF Java classloader monitor
// Attaches uprobes to JVM to trace class loading events
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define MAX_CLASS_NAME 128
#define MAX_SOURCE_LEN 128

struct class_load_event {
    __u32 pid;
    __u32 tid;
    __u64 timestamp;
    __u8  has_source;
    __u8  shared;
    __u16 name_len;
    char  class_name[MAX_CLASS_NAME];
    char  source[MAX_SOURCE_LEN];
};

static volatile int running = 1;
static int verbose = 0;
static int only_non_shared = 0;

static void sig_handler(int sig) {
    running = 0;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct class_load_event *e = data;

    // Optionally filter out shared (CDS) classes
    if (only_non_shared && e->shared)
        return 0;

    // Timestamp formatting
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    char time_buf[32];
    struct tm *tm = localtime(&ts.tv_sec);
    strftime(time_buf, sizeof(time_buf), "%H:%M:%S", tm);

    // Convert JVM internal class name (/ to .)
    char class_name[MAX_CLASS_NAME];
    strncpy(class_name, e->class_name, MAX_CLASS_NAME - 1);
    class_name[MAX_CLASS_NAME - 1] = '\0';
    for (int i = 0; class_name[i]; i++) {
        if (class_name[i] == '/')
            class_name[i] = '.';
    }

    if (e->has_source && e->source[0]) {
        printf("[%s] pid=%d tid=%d  %s%s  source=%s\n",
               time_buf, e->pid, e->tid,
               class_name,
               e->shared ? " [shared]" : "",
               e->source);
    } else {
        printf("[%s] pid=%d tid=%d  %s%s\n",
               time_buf, e->pid, e->tid,
               class_name,
               e->shared ? " [shared]" : "");
    }

    fflush(stdout);
    return 0;
}

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s [options] -p PID\n", prog);
    fprintf(stderr, "       %s [options] -l /path/to/libjvm.so\n", prog);
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  -p PID      Attach to running JVM process\n");
    fprintf(stderr, "  -l PATH     Path to libjvm.so (for uprobe, required)\n");
    fprintf(stderr, "  -v          Verbose output\n");
    fprintf(stderr, "  -n          Only show non-shared classes (not from CDS)\n");
    fprintf(stderr, "  -h          Show this help\n");
}

int main(int argc, char **argv) {
    struct bpf_object *obj = NULL;
    struct bpf_program *uprobe_prog = NULL;
    struct bpf_link *uprobe_link = NULL;
    struct bpf_link *usdt_link = NULL;
    struct ring_buffer *rb = NULL;
    int err, opt;
    int target_pid = -1;
    const char *libjvm_path = NULL;

    while ((opt = getopt(argc, argv, "p:l:vnh")) != -1) {
        switch (opt) {
        case 'p':
            target_pid = atoi(optarg);
            break;
        case 'l':
            libjvm_path = optarg;
            break;
        case 'v':
            verbose = 1;
            break;
        case 'n':
            only_non_shared = 1;
            break;
        case 'h':
        default:
            usage(argv[0]);
            return opt == 'h' ? 0 : 1;
        }
    }

    if (target_pid < 0) {
        fprintf(stderr, "ERROR: -p PID is required\n");
        usage(argv[0]);
        return 1;
    }

    // Auto-detect libjvm.so path from /proc/PID/maps if not specified
    if (!libjvm_path) {
        static char detected_path[512];
        char maps_path[64];
        snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", target_pid);
        FILE *f = fopen(maps_path, "r");
        if (f) {
            char line[1024];
            while (fgets(line, sizeof(line), f)) {
                char *p = strstr(line, "libjvm.so");
                if (p) {
                    // Extract path: find the start of path (after permissions etc.)
                    char *path_start = strchr(line, '/');
                    if (path_start) {
                        char *nl = strchr(path_start, '\n');
                        if (nl) *nl = '\0';
                        strncpy(detected_path, path_start, sizeof(detected_path) - 1);
                        libjvm_path = detected_path;
                        break;
                    }
                }
            }
            fclose(f);
        }
    }

    if (!libjvm_path) {
        fprintf(stderr, "ERROR: could not find libjvm.so for PID %d. Use -l to specify path.\n", target_pid);
        return 1;
    }

    if (verbose)
        printf("Using libjvm.so: %s\n", libjvm_path);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Open BPF object
    obj = bpf_object__open_file("jclass_monitor.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object failed\n");
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: loading BPF object failed: %d\n", err);
        goto cleanup;
    }

    // Attach uprobe to JVM_DefineClassWithSource
    uprobe_prog = bpf_object__find_program_by_name(obj, "uprobe_define_class_with_source");
    if (uprobe_prog) {
        // Find the symbol offset
        LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts,
            .func_name = "JVM_DefineClassWithSource",
            .retprobe = false,
        );
        uprobe_link = bpf_program__attach_uprobe_opts(uprobe_prog, target_pid,
                                                       libjvm_path, 0, &uprobe_opts);
        if (libbpf_get_error(uprobe_link)) {
            fprintf(stderr, "WARNING: attaching uprobe to JVM_DefineClassWithSource failed\n");
            uprobe_link = NULL;
        } else if (verbose) {
            printf("Attached uprobe to JVM_DefineClassWithSource\n");
        }
    }

    // Attach USDT probe for hotspot:class__loaded
    struct bpf_program *usdt_prog = bpf_object__find_program_by_name(obj, "usdt_class_loaded");
    if (usdt_prog) {
        LIBBPF_OPTS(bpf_usdt_opts, usdt_opts);
        // Note: libbpf USDT API requires bpf_program__attach_usdt
        // which needs provider="hotspot", name="class__loaded"
        // This requires the target binary path
        usdt_link = bpf_program__attach_usdt(usdt_prog, target_pid,
                                              libjvm_path,
                                              "hotspot", "class__loaded",
                                              NULL);
        if (libbpf_get_error(usdt_link)) {
            fprintf(stderr, "WARNING: attaching USDT hotspot:class__loaded failed: %ld\n",
                    libbpf_get_error(usdt_link));
            usdt_link = NULL;
        } else if (verbose) {
            printf("Attached USDT probe hotspot:class__loaded\n");
        }
    }

    if (!uprobe_link && !usdt_link) {
        fprintf(stderr, "ERROR: no probes could be attached\n");
        err = 1;
        goto cleanup;
    }

    printf("Java classloader monitor attached to PID %d\n", target_pid);
    if (uprobe_link) printf("  uprobe: JVM_DefineClassWithSource\n");
    if (usdt_link) printf("  USDT:   hotspot:class__loaded\n");
    if (only_non_shared) printf("  Filter: showing only non-shared classes\n");
    printf("Press Ctrl+C to stop.\n\n");

    // Set up ring buffer
    int map_fd = bpf_object__find_map_fd_by_name(obj, "events");
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

    printf("\nDetaching probes...\n");

cleanup:
    if (rb)
        ring_buffer__free(rb);
    if (uprobe_link)
        bpf_link__destroy(uprobe_link);
    if (usdt_link)
        bpf_link__destroy(usdt_link);
    if (obj)
        bpf_object__close(obj);

    return err != 0;
}
