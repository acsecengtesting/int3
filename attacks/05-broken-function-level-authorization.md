# Broken Function Level Authorization

## OWASP Classification
API5:2023 — Broken Function Level Authorization

## Attack Class Description

The application exposes administrative or privileged endpoints that are
not properly protected. Attackers discover hidden endpoints (admin panels,
internal APIs, actuator endpoints) and invoke them without proper authz.

In Java: Spring Boot Actuator endpoints (/actuator/env, /actuator/heapdump),
admin controllers, internal service-to-service APIs exposed externally.

## eBPF Detection Signals

### Signal 1: Access to management/actuator endpoints

**Hook**: Cannot detect HTTP URL paths from eBPF directly (TLS encrypted).

However, we CAN detect the consequences of actuator abuse:
- `/actuator/heapdump` causes large memory reads and outbound data transfer
- `/actuator/env` may trigger property changes
- `/actuator/shutdown` triggers JVM shutdown

**Detection logic for heapdump theft**:
- Track outbound TCP data volume per response
- A single response >100MB from a Java API container is unusual
- Alert on response sizes that exceed normal API payload thresholds

**Practicality**: MEDIUM — can detect large data exfiltration but not the
specific endpoint being accessed.

### Signal 2: Sensitive file access from heap dump

**Hook**: `tracepoint/syscalls/sys_enter_openat`

When the JVM writes a heap dump, it accesses heap memory and writes a
large file. This write to the overlay's writable layer is detectable.

**Detection logic**:
- Alert on large file creation (`.hprof` extension or >100MB) in containers
- Alert on writes to `/tmp/*.hprof` or similar patterns

**Practicality**: HIGH — file creation monitoring is well-suited to eBPF.

### Signal 3: JVM shutdown from external trigger

**Hook**: Signal tracepoints or `sys_enter_kill`

If `/actuator/shutdown` is called, the JVM receives a graceful shutdown.
Unexpected JVM termination in a container that should be long-running
is suspicious.

**Practicality**: LOW — JVM graceful shutdown is hard to distinguish
from normal pod scaling.

## Assessment

**eBPF detection feasibility: LOW-MEDIUM**

Function-level authorization is an application-logic concern that eBPF
cannot directly observe (URLs are encrypted in TLS). However, the
consequences of exploiting these endpoints (large data transfers,
sensitive file access, JVM shutdown) produce detectable kernel-level
signals. The strongest signal is detecting heap dump file creation or
anomalous response sizes.
