#!/bin/bash
# Provision a fresh Ubuntu 24.04 VM for eBPF + Java classloader monitoring
# Run this as root on the new VM after SSH is available
set -e

echo "=== Installing eBPF build tools ==="
apt-get update -qq
apt-get install -y -qq clang llvm gcc make libbpf-dev linux-tools-common \
    linux-tools-generic libelf-dev zlib1g-dev

echo "=== Installing JDK ==="
apt-get install -y -qq default-jdk

echo "=== Verifying installations ==="
java --version
clang --version | head -1
bpftool version 2>/dev/null || echo "bpftool via linux-tools"

echo "=== Creating project directory ==="
mkdir -p /root/jclass_monitor

echo "=== Done ==="
echo "Next: scp the source files and run 'make' in /root/jclass_monitor"
