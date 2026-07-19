// SPDX-License-Identifier: GPL-2.0
// Detect network connections originating from JNI native code (exploited .so).
//
// Entirely kernel-side detection using bpf_find_vma to resolve user-stack IPs
// to their backing .so files at connect() time.
//
// Normal Java networking flows through libnet.so/libnio.so → libc connect().
// An exploited JNI library making direct socket calls will have a non-networking
// .so on the stack between the JIT code and libc.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

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
    char  suspicious_lib[MAX_FILENAME];  // the .so that's NOT a networking lib
    char  comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} jni_net_events SEC(".maps");

// Callback context passed between kprobe and bpf_find_vma callback
struct vma_check_ctx {
    __u8 found_suspicious;
    char lib_name[MAX_FILENAME];
};

// Names of known-safe libraries for networking
// If a .so frame is NOT one of these and NOT anonymous, it's suspicious
static __always_inline int is_safe_networking_lib(const char *name) {
    // Check for known JDK and system libs that legitimately call connect()
    // libnet.so, libnio.so — JDK networking natives
    if (name[0] == 'l' && name[1] == 'i' && name[2] == 'b') {
        // libnet.so
        if (name[3] == 'n' && name[4] == 'e' && name[5] == 't' && name[6] == '.')
            return 1;
        // libnio.so
        if (name[3] == 'n' && name[4] == 'i' && name[5] == 'o' && name[6] == '.')
            return 1;
        // libc.so or libc-
        if (name[3] == 'c' && (name[4] == '.' || name[4] == '-'))
            return 1;
        // libjvm.so
        if (name[3] == 'j' && name[4] == 'v' && name[5] == 'm' && name[6] == '.')
            return 1;
        // libjava.so
        if (name[3] == 'j' && name[4] == 'a' && name[5] == 'v' && name[6] == 'a')
            return 1;
        // libpthread
        if (name[3] == 'p' && name[4] == 't' && name[5] == 'h')
            return 1;
        // libextnet.so
        if (name[3] == 'e' && name[4] == 'x' && name[5] == 't')
            return 1;
        // libz, libm, libdl, librt
        if (name[3] == 'z' || name[3] == 'm' || name[3] == 'd' || name[3] == 'r')
            return 1;
        // libverify
        if (name[3] == 'v' && name[4] == 'e' && name[5] == 'r')
            return 1;
        // libjli
        if (name[3] == 'j' && name[4] == 'l' && name[5] == 'i')
            return 1;
        // libjimage
        if (name[3] == 'j' && name[4] == 'i' && name[5] == 'm')
            return 1;
        // libjsvml
        if (name[3] == 'j' && name[4] == 's' && name[5] == 'v')
            return 1;
    }
    // ld-linux
    if (name[0] == 'l' && name[1] == 'd' && name[2] == '-')
        return 1;
    return 0;
}

// Check if a filename is a .so (shared library)
static __always_inline int is_shared_lib_name(const char *name) {
    #pragma unroll
    for (int i = 0; i < MAX_FILENAME - 3; i++) {
        if (name[i] == '\0')
            return 0;
        if (name[i] == '.' && name[i+1] == 's' && name[i+2] == 'o')
            return 1;
    }
    return 0;
}

// Callback for bpf_find_vma — called with the VMA containing a user-stack IP
static long vma_check_callback(struct task_struct *task, struct vm_area_struct *vma, void *ctx)
{
    struct vma_check_ctx *check = (struct vma_check_ctx *)ctx;

    // If we already found something suspicious, skip
    if (check->found_suspicious)
        return 0;

    // Get the backing file of this VMA
    struct file *vm_file = BPF_CORE_READ(vma, vm_file);
    if (!vm_file)
        return 0;  // Anonymous mapping (JIT code, heap) — skip

    // Read the filename
    char name[MAX_FILENAME] = {};
    struct dentry *dentry = BPF_CORE_READ(vm_file, f_path.dentry);
    if (!dentry)
        return 0;

    bpf_probe_read_kernel_str(name, sizeof(name), BPF_CORE_READ(dentry, d_name.name));

    // Only care about shared libraries
    if (!is_shared_lib_name(name))
        return 0;

    // Check if this is a known safe networking/system library
    if (is_safe_networking_lib(name))
        return 0;

    // This is a .so that's NOT a known networking library — suspicious!
    check->found_suspicious = 1;
    __builtin_memcpy(check->lib_name, name, MAX_FILENAME);

    return 0;
}

SEC("kprobe/tcp_connect")
int BPF_KPROBE(kprobe_tcp_connect, struct sock *sk)
{
    // Capture user-space stack
    __u64 user_stack[MAX_STACK_DEPTH] = {};
    int stack_sz = bpf_get_stack(ctx, user_stack, sizeof(user_stack), BPF_F_USER_STACK);
    if (stack_sz <= 0)
        return 0;

    int depth = stack_sz / 8;
    if (depth <= 0 || depth > MAX_STACK_DEPTH)
        return 0;

    // For each stack frame, check what .so it belongs to
    struct task_struct *task = bpf_get_current_task_btf();
    struct vma_check_ctx check = {};

    #pragma unroll
    for (int i = 0; i < MAX_STACK_DEPTH; i++) {
        if (i >= depth)
            break;
        if (user_stack[i] == 0)
            continue;
        if (check.found_suspicious)
            break;

        bpf_find_vma(task, user_stack[i], vma_check_callback, &check, 0);
    }

    if (!check.found_suspicious)
        return 0;

    // A non-networking .so is on the call stack for this connect() — alert
    struct jni_connect_event *e = bpf_ringbuf_reserve(&jni_net_events, sizeof(*e), 0);
    if (!e)
        return 0;

    __u32 pid_tgid_hi = bpf_get_current_pid_tgid() >> 32;
    e->pid = pid_tgid_hi;
    e->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->timestamp = bpf_ktime_get_ns();
    e->mnt_ns_inum = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
    e->dest_addr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    e->dest_port = BPF_CORE_READ(sk, __sk_common.skc_dport);
    e->stack_depth = depth < MAX_STACK_DEPTH ? depth : MAX_STACK_DEPTH;

    #pragma unroll
    for (int i = 0; i < MAX_STACK_DEPTH; i++)
        e->user_stack[i] = user_stack[i];

    __builtin_memcpy(e->suspicious_lib, check.lib_name, MAX_FILENAME);
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
