# Makefile for eBPF Java classloader monitor
CLANG := clang
CC := gcc
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH)
USER_CFLAGS := -O2 -g -Wall
USER_LDFLAGS := -lbpf -lelf -lz

.PHONY: all clean vmlinux

all: vmlinux.h jclass_monitor.bpf.o jclass_monitor

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

jclass_monitor.bpf.o: jclass_monitor.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

jclass_monitor: jclass_monitor.c
	$(CC) $(USER_CFLAGS) -o $@ $< $(USER_LDFLAGS)

clean:
	rm -f jclass_monitor.bpf.o jclass_monitor vmlinux.h
