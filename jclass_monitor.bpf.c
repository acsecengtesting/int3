// SPDX-License-Identifier: GPL-2.0
// eBPF uprobe program to log Java class loading
// Hooks into JVM via:
//   1. USDT hotspot:class__loaded - fires for every class load
//   2. uprobe on JVM_DefineClassWithSource - captures class source/path
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/usdt.bpf.h>

#define MAX_CLASS_NAME 128
#define MAX_SOURCE_LEN 128

// Event emitted for each class load
struct class_load_event {
    __u32 pid;
    __u32 tid;
    __u64 timestamp;
    __u8  has_source;
    __u8  shared;          // loaded from shared archive (CDS)
    __u16 name_len;
    char  class_name[MAX_CLASS_NAME];
    char  source[MAX_SOURCE_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} events SEC(".maps");

// Hook JVM_DefineClassWithSource to capture where class bytecode comes from
// Signature: JVM_DefineClassWithSource(JNIEnv *env, const char *name,
//            jobject loader, const jbyte *buf, jsize len, jobject pd,
//            const char *source)
// x86_64 ABI: name=%rsi, source=stack (7th arg)
// However, with uprobe we get PT_REGS: arg1=rdi, arg2=rsi, arg3=rdx, etc.
// 7th arg is at [rsp+8] at function entry
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
    e->has_source = 1;
    e->shared = 0;
    e->name_len = 0;

    __builtin_memset(e->class_name, 0, MAX_CLASS_NAME);
    __builtin_memset(e->source, 0, MAX_SOURCE_LEN);

    // Read class name from userspace
    if (name) {
        bpf_probe_read_user_str(e->class_name, MAX_CLASS_NAME, name);
        // Calculate length
        #pragma unroll
        for (int i = 0; i < MAX_CLASS_NAME; i++) {
            if (e->class_name[i] == '\0')
                break;
            e->name_len++;
        }
    }

    // Read source (7th argument) from stack
    // At uprobe entry, 7th arg is at RSP+8 (return address is at RSP)
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
// The USDT probe arguments from readelf:
//   arg0: 8@%rdx  - class name pointer
//   arg1: -4@%eax - class name length (signed 32-bit)  
//   arg2: 8@152(%rdi) - classloader pointer
//   arg3: 1@%cl   - shared flag
// BPF_USDT args are all passed as (void*) by the macro
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
    e->has_source = 0;
    e->shared = (__u8)shared_flag;
    e->name_len = name_len > MAX_CLASS_NAME ? MAX_CLASS_NAME : name_len;

    __builtin_memset(e->class_name, 0, MAX_CLASS_NAME);
    __builtin_memset(e->source, 0, MAX_SOURCE_LEN);

    if (class_name_ptr && name_len > 0) {
        // Use unsigned and mask to prove to verifier value is bounded
        __u32 read_len = (__u32)name_len & (MAX_CLASS_NAME - 1);
        bpf_probe_read_user(e->class_name, read_len + 1, class_name_ptr);
        e->class_name[read_len] = '\0';
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
