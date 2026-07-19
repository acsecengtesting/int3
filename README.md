# eBPF Java Runtime Security Monitor

Kernel-side detection of suspicious Java runtime behaviour in containers using eBPF. No Java agents, no JVM modifications, no userspace path resolution.

## Detectors

### 1. Java Classloader Monitor (`jclass_monitor`)

Hooks into the JVM to observe class loading activity without modifying the JVM.

**Probes:**
- **USDT `hotspot:class__loaded`** — fires on every class load, reports class name and whether it came from the shared archive (CDS)
- **Uprobe `JVM_DefineClassWithSource`** — captures the source path (jar/module URI), bytecode size, and FNV hash of the class bytes
- **Uprobe `JVM_LoadLibrary`** — logs every native library loaded via `System.loadLibrary()` / `System.load()`
- **Tracepoint `sys_enter_execve`** — detects process execution from the JVM or its children (catches `Runtime.exec()`, `ProcessBuilder`, or native code spawning processes)

**Test results:**
```
[10:03:11] pid=13240 tid=13242  com.example.HelloPlugin  bytes=524 crc=0x09f2898f  source=file:/root/jclass_monitor/testplugin.jar
[10:03:11] pid=13240 tid=13242  [NATIVE LIB] /usr/lib/jvm/java-21-openjdk-amd64/lib/libnio.so
[10:03:11] pid=13240 tid=13242  [NATIVE LIB] /usr/lib/jvm/java-21-openjdk-amd64/lib/libzip.so
[10:10:40] pid=14306 tid=14306  [EXEC] /usr/bin/id  (ppid=14289)
[10:10:40] pid=14308 tid=14308  [EXEC] /usr/bin/whoami  (ppid=14289)
```

### 2. Overlay Writable-Layer Detector (`ovl_detect`)

Detects `.so`, `.class`, and `.jar` files being accessed from the writable (upper) overlay layer inside a container. Files in the read-only image layers do not trigger alerts.

**Probe:**
- **Kprobe `ovl_open`** — fires on every file open through overlayfs. Uses `container_of` to reach `ovl_inode.__upperdentry` to determine if the file is in the upper (writable) layer. Filters to non-host mount namespaces (containers only).

**Test results:**
```
[11:28:41] ALERT: .so from WRITABLE layer in container
       pid=13205 comm=cp mnt_ns=4026532418
       file=tmp/evil.so

[11:28:41] ALERT: .class from WRITABLE layer in container
       pid=13385 comm=javac mnt_ns=4026532418
       file=tmp/Pwned.class

[11:28:41] ALERT: .class from WRITABLE layer in container
       pid=13415 comm=java mnt_ns=4026532418
       file=tmp/Pwned.class

[11:28:41] ALERT: .jar from WRITABLE layer in container
       pid=13307 comm=cp mnt_ns=4026532418
       file=tmp/evil.jar
```

Files from the read-only image layers (e.g. `/opt/java/openjdk/lib/libjava.so`) produce no alerts.

### 3. JNI Exploit Network Detector (`jni_net`)

Detects outbound network connections where the call originates from native code inside a JNI library rather than through Java's standard networking stack.

**Probe:**
- **Kprobe `tcp_connect`** — on every outbound TCP connection, captures the user-space stack with `bpf_get_stack(BPF_F_USER_STACK)`, then uses `bpf_find_vma` to resolve each stack frame's IP to its backing `.so` file via the kernel's VMA tree. If any frame is in a `.so` that is NOT a known JDK/system networking library (`libnet.so`, `libnio.so`, `libc.so`, `libjvm.so`, etc.), an alert fires with the name of the suspicious library.

**Test results:**

Normal Java `Socket.connect()` — no alert (all frames in safe JDK libs):
```
(no output)
```

JNI native library calling `connect()` directly — alert:
```
[11:49:12] ALERT: Non-networking native lib on connect() stack!
       pid=17142 comm=java mnt_ns=4026532418
       dest=93.184.216.34:80
       suspicious_lib=libnativenet.so
       stack:
         [0] 0x7ecab184e9db
         [1] 0x7ecaaebec278
         ...
```

## Design Principles

- **No JVM modification** — no agents, no flags, no bytecode manipulation
- **No userspace path resolution** — all detection logic runs in kernel context using BTF, `bpf_find_vma`, and `BPF_CORE_READ`
- **Container-aware** — uses mount namespace inode numbers and overlay inode internals to distinguish container vs host, and writable vs read-only layers
- **Low overhead** — kprobes and USDT probes fire only on the specific events of interest

## Building

Requires: Linux 6.1+, clang, libbpf-dev, libelf-dev, bpftool

```bash
# Generate vmlinux.h
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Build BPF objects
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu \
    -c ovl_detect.bpf.c -o ovl_detect.bpf.o
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu \
    -c jni_net.bpf.c -o jni_net.bpf.o
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu \
    -c jclass_monitor.bpf.c -o jclass_monitor.bpf.o

# Build userspace loaders
gcc -O2 -g -Wall -o ovl_detect ovl_detect.c -lbpf -lelf -lz
gcc -O2 -g -Wall -o jni_net jni_net.c -lbpf -lelf -lz
gcc -O2 -g -Wall -o jclass_monitor jclass_monitor.c -lbpf -lelf -lz
```

## Usage

```bash
# Detect .so/.class/.jar from writable container layers (runs system-wide)
./ovl_detect

# Detect JNI exploit network connections (runs system-wide)
./jni_net

# Monitor a specific JVM process
./jclass_monitor -v -p <PID>
```
