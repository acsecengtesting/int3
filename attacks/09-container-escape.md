# Container Escape

## OWASP Classification
Not in API Top 10 — this is a post-compromise infrastructure attack that follows code execution within a container.

## Attack Class Description

After gaining code execution inside a container, an attacker attempts to break out of container isolation to access the host or other containers. Common techniques:

- **Privileged container abuse**: mounting host filesystems, accessing host devices
- **Docker socket access**: if `/var/run/docker.sock` is mounted, attacker can control Docker
- **Kernel exploits**: CVEs in the kernel or runc (e.g., CVE-2019-5736) to overwrite host binaries
- **hostPID/hostNetwork**: namespace sharing allows access to host processes/network
- **nsenter**: entering the host's namespaces from a privileged container
- **procfs escape**: writing to `/proc/sys` or `/proc/sysrq-trigger` from a poorly isolated container

## eBPF Detection Signals

### Signal 1: Mount syscall from within a container

**Hook**: `tracepoint/syscalls/sys_enter_mount`

Containers should almost never call `mount()`. An attacker trying to mount the host filesystem (e.g., `mount /dev/sda1 /mnt`) is a clear escape attempt.

**Detection logic**:
- Filter to container mount namespaces
- Any `mount()` syscall from a container = alert
- Capture the source device and target path

**Practicality**: VERY HIGH — containers should not mount filesystems. Near-zero false positives.

### Signal 2: Namespace manipulation (setns, unshare)

**Hook**: `tracepoint/syscalls/sys_enter_setns` / `tracepoint/syscalls/sys_enter_unshare`

Joining or creating new namespaces is the core mechanic of container escape. A process calling `setns()` to join the host's PID or mount namespace is escaping.

**Detection logic**:
- Any `setns()` or `unshare()` from within a container = critical alert
- Capture the namespace file descriptor and type

**Practicality**: VERY HIGH — these syscalls have no legitimate use from inside a normal Java application container.

### Signal 3: Access to Docker socket

**Hook**: `tracepoint/syscalls/sys_enter_connect` (Unix socket)

If the Docker socket is mounted in the container, an attacker connecting to it gains full host control.

**Detection logic**:
- Detect `connect()` to Unix domain socket with path `/var/run/docker.sock`
- Filter to container processes

**Practicality**: VERY HIGH — clear signal, no legitimate reason for a Java app to talk to Docker socket.

### Signal 4: Write to sensitive host paths

**Hook**: `tracepoint/syscalls/sys_enter_openat` with O_WRONLY

Escape via writing to host-mapped paths: `/proc/sysrq-trigger`, `/proc/sys/kernel/core_pattern`, cgroup release_agent, etc.

**Detection logic**:
- Monitor writes to `/proc/sys/`, `/proc/sysrq-trigger`
- Monitor writes to cgroup files (release_agent)
- Alert on any write to these paths from container processes

**Practicality**: VERY HIGH — these writes are never legitimate from application containers.

### Signal 5: ptrace from within a container

**Hook**: `tracepoint/syscalls/sys_enter_ptrace`

Attacker using `ptrace` to attach to processes (potentially host processes if hostPID is enabled).

**Detection logic**:
- Any `ptrace` syscall from a container = alert

**Practicality**: VERY HIGH — Java applications never use ptrace.

## Assessment

**eBPF detection feasibility: VERY HIGH**

Container escape attempts produce unmistakable kernel-level signals. The syscalls involved (`mount`, `setns`, `unshare`, `ptrace`, writes to `/proc`) are never used by legitimate Java web applications. eBPF-based detection of these syscalls is the gold standard approach — this is exactly what tools like Falco and Tetragon implement.
