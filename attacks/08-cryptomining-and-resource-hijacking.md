# Cryptomining and Resource Hijacking

## OWASP Classification
Not directly in OWASP Top 10 — this is a post-compromise activity that follows from any of the above attack classes achieving code execution.

## Attack Class Description

After gaining code execution inside a container (via any vulnerability), attackers deploy cryptocurrency miners. This is the most common post-exploitation activity in containerised environments because:
- Containers have CPU/GPU resources available
- Cloud billing absorbs the cost (victim pays)
- Minimal detection in many environments
- No data exfiltration needed (just compute theft)

Miners are typically downloaded to `/tmp`, `/dev/shm`, or memory-only, then connect to mining pools over stratum+tcp protocol (usually port 3333, 4444, 5555, or similar).

## eBPF Detection Signals

### Signal 1: Binary execution from writable paths

**Hook**: `tracepoint/syscalls/sys_enter_execve`

Cryptominers are executed from writable locations: `/tmp`, `/dev/shm`, `/var/tmp`, or anonymous memory. A Java container should never execute binaries from these paths.

**Detection logic**:
- Check the first argument to `execve` (filename)
- Alert if the path starts with `/tmp/`, `/dev/shm/`, `/var/tmp/`
- Alert if the binary doesn't exist in the original image (writable layer check)

**Practicality**: VERY HIGH — trivial to detect, near-zero false positives.

### Signal 2: Outbound connections to mining pool ports

**Hook**: `kprobe:tcp_connect`

Mining pools typically use ports 3333, 4444, 5555, 14433, 14444 with stratum protocol. A containerised Java web app has no legitimate reason to connect to these ports.

**Detection logic**:
- Alert on outbound connections from container PIDs to known mining ports
- Can also check for stratum protocol handshake patterns in early bytes

**Practicality**: VERY HIGH — port-based detection is simple and effective.

### Signal 3: High sustained CPU usage without corresponding network I/O change

**Hook**: `sched_switch` tracepoint + network counters

A cryptominer produces high CPU but minimal network traffic (small stratum protocol messages). A web app should show correlated CPU and network activity. High CPU with flat network = suspicious.

**Detection logic**:
- Track on-CPU time per cgroup/container
- Track network bytes per container
- Alert when CPU usage is high (>80%) but outbound bytes are low for extended period

**Practicality**: MEDIUM — requires ratio analysis and baselining.

### Signal 4: Suspicious DNS lookups for mining pools

**Hook**: DNS monitoring (our existing DNS XDP/TC approach)

Miners resolve pool domains like `pool.minexmr.com`, `xmr.pool.minergate.com`, etc. These domains are not in a normal web app's DNS queries.

**Detection logic**:
- Match DNS queries against a list of known mining pool domains
- Alert on high-entropy subdomain queries (used by some pools for worker identification)

**Practicality**: HIGH — domain-based detection is straightforward.

### Signal 5: File written then immediately executed

**Hook**: `tracepoint/syscalls/sys_enter_openat` + `tracepoint/syscalls/sys_enter_execve`

The pattern: write a binary to `/tmp`, `chmod +x`, then execute it. Track write-then-exec sequences within a container.

**Detection logic**:
- Track files created in writable directories
- If the same file is then executed within a short window, alert

**Practicality**: HIGH — sequential syscall correlation is well-suited to BPF maps.

## Assessment

**eBPF detection feasibility: VERY HIGH**

Cryptomining is one of the most detectable post-compromise activities. The signals (binary execution from /tmp, connections to mining ports, high CPU with low network, suspicious DNS) are all strongly observable from eBPF and have very low false positive rates in containerised Java applications.
