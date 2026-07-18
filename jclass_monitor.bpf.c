// SPDX-License-Identifier: GPL-2.0
// eBPF uprobe program to log Java class loading
// Hooks into JVM via:
//   1. USDT hotspot:class__loaded - fires for every class load (including CDS)
//   2. uprobe on JVM_DefineClassWithSource - captures class source/path + bytecode hash
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/usdt.bpf.h>

#define MAX_CLASS_NAME 128
#define MAX_SOURCE_LEN 128

// Event types
#define EVT_USDT_LOADED  1   // from USDT hotspot:class__loaded
#define EVT_DEFINE_CLASS 2   // from uprobe JVM_DefineClassWithSource
#define EVT_LOAD_LIBRARY 3   // from uprobe JVM_LoadLibrary (JNI native lib)
#define EVT_EXEC         4   // from tracepoint sys_enter_execve (process execution)

// Event emitted for each class load
struct class_load_event {
    __u32 pid;
    __u32 tid;
    __u64 timestamp;
    __u8  event_type;      // EVT_USDT_LOADED or EVT_DEFINE_CLASS
    __u8  shared;          // loaded from shared archive (CDS)
    __u16 name_len;
    __u32 bytecode_len;    // size of class bytecode (from DefineClass)
    __u32 bytecode_crc;    // simple hash of first bytes of bytecode
    char  class_name[MAX_CLASS_NAME];
    char  source[MAX_SOURCE_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} events SEC(".maps");

// Simple FNV-1a hash of the first 64 bytes of bytecode
static __always_inline __u32 hash_bytes(const void *buf, __u32 len) {
    __u32 hash = 0x811c9dc5;  // FNV offset basis
    __u8 bytes[64] = {};

    // Always read exactly 64 bytes (padding with zeros if shorter)
    __u32 to_read = len < 64 ? len : 64;
    to_read &= 63;  // verifier-friendly bound

    if (bpf_probe_read_user(bytes, sizeof(bytes), buf) != 0)
        return 0;

    // Hash all 64 bytes (zeros beyond actual data are fine for fingerprinting)
    #pragma unroll
    for (int i = 0; i < 64; i++) {
        hash ^= bytes[i];
        hash *= 0x01000193;  // FNV prime
    }
    return hash;
}

// Hook JVM_DefineClassWithSource to capture where class bytecode comes from
// Signature: JVM_DefineClassWithSource(JNIEnv *env, const char *name,
//            jobject loader, const jbyte *buf, jsize len, jobject pd,
//            const char *source)
// x86_64 ABI: arg1-6 in rdi,rsi,rdx,rcx,r8,r9; arg7 on stack at rsp+8
SEC("uprobe")
int BPF_KPROBE(uprobe_define_class_with_source,
               void *env,           // %rdi - JNIEnv
               const char *name,    // %rsi - class name
               void *loader,        // %rdx - classloader
               const void *buf,     // %rcx - bytecode buffer
               int len,             // %r8  - bytecode length
               void *pd)            // %r9  - protection domain
               // const char *source - on stack, %rsp+8
{
    struct class_load_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->timestamp = bpf_ktime_get_ns();
    e->event_type = EVT_DEFINE_CLASS;
    e->shared = 0;
    e->name_len = 0;
    e->bytecode_len = (__u32)len;
    e->bytecode_crc = 0;

    __builtin_memset(e->class_name, 0, MAX_CLASS_NAME);
    __builtin_memset(e->source, 0, MAX_SOURCE_LEN);

    // Read class name from userspace
    if (name) {
        bpf_probe_read_user_str(e->class_name, MAX_CLASS_NAME, name);
        #pragma unroll
        for (int i = 0; i < MAX_CLASS_NAME; i++) {
            if (e->class_name[i] == '\0')
                break;
            e->name_len++;
        }
    }

    // Hash the bytecode for fingerprinting
    if (buf && len > 0) {
        e->bytecode_crc = hash_bytes(buf, (__u32)len);
    }

    // Read source (7th argument) from stack
    // At uprobe entry, return address is at RSP, 7th arg at RSP+8
    struct pt_regs *regs = (struct pt_regs *)ctx;
    __u64 sp = PT_REGS_SP(regs);
    const char *source = NULL;
    bpf_probe_read_user(&source, sizeof(source), (void *)(sp + 8));
    if (source) {
        bpf_probe_read_user_str(e->source, MAX_SOURCE_LEN, source);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// USDT probe: hotspot:class__loaded
// Arguments from readelf:
//   arg0: 8@%rdx  - class name pointer
//   arg1: -4@%eax - class name length (signed 32-bit)
//   arg2: 8@152(%rdi) - classloader pointer
//   arg3: 1@%cl   - shared flag
SEC("usdt")
int BPF_USDT(usdt_class_loaded, void *arg0, void *arg1, void *arg2, void *arg3)
{
    struct class_load_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    void *class_name_ptr = arg0;
    int name_len = (int)(long)arg1;
    int shared_flag = (int)(long)arg3;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->timestamp = bpf_ktime_get_ns();
    e->event_type = EVT_USDT_LOADED;
    e->shared = (__u8)shared_flag;
    e->name_len = name_len > MAX_CLASS_NAME ? MAX_CLASS_NAME : name_len;
    e->bytecode_len = 0;
    e->bytecode_crc = 0;

    __builtin_memset(e->class_name, 0, MAX_CLASS_NAME);
    __builtin_memset(e->source, 0, MAX_SOURCE_LEN);

    if (class_name_ptr && name_len > 0) {
        __u32 read_len = (__u32)name_len & (MAX_CLASS_NAME - 1);
        bpf_probe_read_user(e->class_name, read_len + 1, class_name_ptr);
        e->class_name[read_len] = '\0';
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Map to store the target PID we're monitoring
// Userspace sets this; the execve tracepoint checks against it
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u8);
} target_pids SEC(".maps");

// Hook JVM_LoadLibrary to detect native library loads (JNI)
// Signature: void* JVM_LoadLibrary(const char *name, jboolean throwException)
// This fires when System.loadLibrary() or System.load() is called
SEC("uprobe")
int BPF_KPROBE(uprobe_load_library, const char *lib_name)
{
    struct class_load_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->timestamp = bpf_ktime_get_ns();
    e->event_type = EVT_LOAD_LIBRARY;
    e->shared = 0;
    e->name_len = 0;
    e->bytecode_len = 0;
    e->bytecode_crc = 0;

    __builtin_memset(e->class_name, 0, MAX_CLASS_NAME);
    __builtin_memset(e->source, 0, MAX_SOURCE_LEN);

    // Library path goes in source field
    if (lib_name) {
        bpf_probe_read_user_str(e->source, MAX_SOURCE_LEN, lib_name);
        // Copy short name into class_name for display
        bpf_probe_read_user_str(e->class_name, MAX_CLASS_NAME, lib_name);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Tracepoint: sys_enter_execve
// Catches all process executions - filtered to target PID and its children
// This detects Runtime.exec(), ProcessBuilder, or any native code spawning processes
SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint_execve(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 ppid;

    // Check if this PID or its parent is in our target set
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    ppid = BPF_CORE_READ(task, real_parent, tgid);

    __u8 *found = bpf_map_lookup_elem(&target_pids, &pid);
    if (found)
        goto do_log;

    __u8 *parent_found = bpf_map_lookup_elem(&target_pids, &ppid);
    if (!parent_found)
        return 0;

do_log:
    ;

    // This exec is from our target process or its child — log it
    struct class_load_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = pid;
    e->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->timestamp = bpf_ktime_get_ns();
    e->event_type = EVT_EXEC;
    e->shared = 0;
    e->name_len = 0;
    e->bytecode_len = 0;
    e->bytecode_crc = ppid;  // stash parent pid in crc field

    __builtin_memset(e->class_name, 0, MAX_CLASS_NAME);
    __builtin_memset(e->source, 0, MAX_SOURCE_LEN);

    // Read the filename (first arg to execve)
    const char *filename = (const char *)ctx->args[0];
    if (filename) {
        bpf_probe_read_user_str(e->class_name, MAX_CLASS_NAME, filename);
    }

    // Read first argument (argv[1]) into source for context
    const char *const *argv = (const char *const *)ctx->args[1];
    if (argv) {
        const char *arg1 = NULL;
        bpf_probe_read_user(&arg1, sizeof(arg1), &argv[1]);
        if (arg1) {
            bpf_probe_read_user_str(e->source, MAX_SOURCE_LEN, arg1);
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
