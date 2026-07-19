# Unrestricted Resource Consumption

## OWASP Classification
API4:2023 — Unrestricted Resource Consumption

## Attack Class Description

The API does not limit the resources a single client can consume. Attackers exploit this to cause denial of service or inflate operational costs. Variants include:
- Missing rate limiting (request flooding)
- Unbounded query complexity (GraphQL depth attacks)
- Large payload uploads consuming memory/disk
- Expensive operations triggered repeatedly (zip bombs, billion-laughs XML)

## eBPF Detection Signals

### Signal 1: CPU consumption spike from a single container

**Hook**: `sched_switch` tracepoint or BPF CPU profiling

Track per-cgroup (per-container) CPU usage. A sudden spike from baseline indicates either legitimate load or an attack.

**Detection logic**:
- Monitor `sched_switch` events, accumulate on-CPU time per cgroup_id
- Alert when a container exceeds N% CPU for sustained period
- Correlate with connection rate (high CPU + high connection rate = likely attack)

**Practicality**: MEDIUM — CPU monitoring is feasible but noisy. Requires baselining.

### Signal 2: Memory consumption growth

**Hook**: `tracepoint/kmem/mm_page_alloc` or reading cgroup memory stats

Track memory allocation patterns. A memory exhaustion attack (e.g., sending a deeply nested JSON that causes the parser to allocate heavily) shows as rapid memory growth.

**Practicality**: LOW — BPF memory tracing is expensive and noisy. Better handled by cgroup memory limits and OOM kill monitoring.

### Signal 3: High inbound network rate from single source

**Hook**: XDP or TC ingress

Count bytes/packets per source IP arriving at the container. Simple threshold-based detection.

**Detection logic**:
- Per-source-IP byte counter in XDP
- Alert when rate exceeds threshold
- Can also count distinct connections per source

**Practicality**: HIGH — XDP-based rate monitoring is extremely efficient and well-proven (used in DDoS mitigation).

### Signal 4: Disk I/O spike (zip bombs, large uploads)

**Hook**: `tracepoint/block/block_rq_issue`

Track block I/O requests from the container's cgroup. Sudden large writes indicate uploaded file processing or extraction.

**Practicality**: MEDIUM — requires cgroup correlation.

## Assessment

**eBPF detection feasibility: MEDIUM**

Resource consumption attacks produce signals at the infrastructure level (CPU, memory, network, disk) which eBPF can observe. However, distinguishing malicious resource use from legitimate spikes requires baselining. The strongest signal is inbound network rate limiting via XDP, which is a proven eBPF use case.
