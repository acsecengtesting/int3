#!/bin/bash
set -e

CPID=$(docker inspect -f '{{.State.Pid}}' testjava)
echo "Container PID: $CPID"

echo ""
echo "=== Full ovl_inode struct from BTF ==="
bpftool btf dump file /sys/kernel/btf/overlay format c | grep -A30 '^struct ovl_inode {'

echo ""
echo "=== ovl_entry struct ==="
bpftool btf dump file /sys/kernel/btf/overlay format c | grep -A20 '^struct ovl_entry {'

echo ""
echo "=== Test: bpftrace reading __upperdentry on file open ==="
timeout 8 bpftrace -e '
#include <linux/fs.h>

kprobe:ovl_open {
    $inode = (struct inode *)arg0;
    $file = (struct file *)arg1;
    // ovl_inode contains __upperdentry at a known offset
    // Read the __upperdentry pointer from the ovl_inode
    // ovl_inode is the container_of the vfs_inode
    // From BTF: vfs_inode is at some offset in ovl_inode
    printf("ovl_open: comm=%s file=%s\n", comm, str($file->f_path.dentry->d_name.name));
}
' &
BPID=$!
sleep 2

# Open a file from lower layer (read-only image)
docker exec testjava cat /opt/java/openjdk/release > /dev/null
# Open a file from upper layer (writable)
docker exec testjava cat /tmp/test_upper.txt > /dev/null

sleep 3
kill $BPID 2>/dev/null
wait $BPID 2>/dev/null
