#!/bin/bash
# Deploy and build the Java classloader monitor on a remote VM
# Usage: ./deploy.sh <VM_IP>
# Requires: SSH key already authorized on the VM

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <VM_IP>"
    exit 1
fi

VM_IP="$1"
SSH="ssh -o StrictHostKeyChecking=no root@$VM_IP"
SCP="scp -o StrictHostKeyChecking=no"
REMOTE_DIR="/root/jclass_monitor"

echo "=== Provisioning VM at $VM_IP ==="
$SCP provision_vm.sh root@$VM_IP:/root/
$SSH "chmod +x /root/provision_vm.sh && /root/provision_vm.sh"

echo ""
echo "=== Uploading source files ==="
$SCP jclass_monitor.bpf.c jclass_monitor.c Makefile TestApp.java run_test.sh root@$VM_IP:$REMOTE_DIR/

echo ""
echo "=== Building ==="
$SSH "cd $REMOTE_DIR && make clean && make"

echo ""
echo "=== Compiling test app ==="
$SSH "cd $REMOTE_DIR && javac TestApp.java"

echo ""
echo "=== Deploy complete ==="
echo "To test: ssh root@$VM_IP '/root/jclass_monitor/run_test.sh'"
