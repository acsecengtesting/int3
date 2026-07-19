// SPDX-License-Identifier: GPL-2.0
// Detect native libraries (.so) loaded from writable overlay layers in containers
// Uses kprobe on ovl_open to inspect whether a file is from the upper (writable) layer
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_FILENAME 128
#define MAX_PATH_COMPONENT 64

// The ovl_inode struct from the overlay module
// We only need the fields up to __upperdentry
struct ovl_inode___local {
    union {
        void *cache;
        const char *lowerdata_redirect;
    };
    const char *redirect;
    __u64 version;
    unsigned long flags;
    struct inode vfs_inode;
    struct dentry *__upperdentry;
} __attribute__((preserve_access_index));

struct ovl_alert_event {
    __u32 pid;
    __u32 tid;
    __u64 timestamp;
    __u64 mnt_ns_inum;      // mount namespace of the process
    __u8  is_upper;         // 1 if file is from writable layer
    char  filename[MAX_FILENAME];
    char  parent_dir[MAX_PATH_COMPONENT];
    char  comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ovl_events SEC(".maps");

// Store the host mount namespace inum (set by userspace at startup)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} host_mnt_ns SEC(".maps");

// Check if a filename ends with ".so" or contains ".so."
static __always_inline int is_shared_lib(const char *name, int len) {
    if (len < 3)
        return 0;
    // Check for ".so" at end
    if (name[len-3] == '.' && name[len-2] == 's' && name[len-1] == 'o')
        return 1;
    // Check for ".so." pattern (versioned like libfoo.so.1)
    for (int i = 0; i < len - 3 && i < MAX_FILENAME - 4; i++) {
        if (name[i] == '.' && name[i+1] == 's' && name[i+2] == 'o' && name[i+3] == '.')
            return 1;
    }
    return 0;
}

SEC("kprobe/ovl_open")
int BPF_KPROBE(kprobe_ovl_open, struct inode *inode, struct file *file)
{
    // Get current task's mount namespace
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u64 mnt_ns_inum = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);

    // Compare with host mount namespace - skip if we're on the host
    __u32 key = 0;
    __u64 *host_ns = bpf_map_lookup_elem(&host_mnt_ns, &key);
    if (host_ns && mnt_ns_inum == *host_ns)
        return 0;

    // Get the filename from the file's dentry
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    if (!dentry)
        return 0;

    // Read filename
    char filename[MAX_FILENAME] = {};
    struct qstr d_name = BPF_CORE_READ(dentry, d_name);
    bpf_probe_read_kernel_str(filename, sizeof(filename), d_name.name);

    // Check if this is a shared library
    int len = d_name.len;
    if (len > MAX_FILENAME)
        len = MAX_FILENAME;
    if (!is_shared_lib(filename, len & (MAX_FILENAME - 1)))
        return 0;

    // Check if the file is from the upper (writable) layer
    // Use container_of to get ovl_inode from vfs_inode
    // ovl_inode->vfs_inode is at a known offset; __upperdentry follows it
    struct ovl_inode___local *oi;
    oi = container_of(inode, struct ovl_inode___local, vfs_inode);

    struct dentry *upper = BPF_CORE_READ(oi, __upperdentry);
    __u8 is_upper = (upper != NULL) ? 1 : 0;

    // Only alert if the .so is from the upper (writable) layer
    if (!is_upper)
        return 0;

    // Emit alert
    struct ovl_alert_event *e = bpf_ringbuf_reserve(&ovl_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->timestamp = bpf_ktime_get_ns();
    e->mnt_ns_inum = mnt_ns_inum;
    e->is_upper = is_upper;

    __builtin_memset(e->filename, 0, MAX_FILENAME);
    bpf_probe_read_kernel_str(e->filename, MAX_FILENAME, d_name.name);

    // Get parent directory name for context
    __builtin_memset(e->parent_dir, 0, MAX_PATH_COMPONENT);
    struct dentry *parent = BPF_CORE_READ(dentry, d_parent);
    if (parent) {
        struct qstr parent_name = BPF_CORE_READ(parent, d_name);
        bpf_probe_read_kernel_str(e->parent_dir, MAX_PATH_COMPONENT, parent_name.name);
    }

    bpf_get_current_comm(e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
