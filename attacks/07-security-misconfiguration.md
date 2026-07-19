# Security Misconfiguration

## OWASP Classification
API8:2023 — Security Misconfiguration / OWASP Top 10 2025: A02

## Attack Class Description

Insecure default configurations, incomplete setups, open cloud storage, misconfigured HTTP headers, unnecessary services, verbose error messages, debug endpoints left enabled in production.

In Java containers:
- Debug ports exposed (JDWP on 5005, JMX on 9010)
- Management endpoints unsecured (Spring Actuator, Jolokia)
- Verbose stack traces in error responses
- Default credentials unchanged
- TLS disabled or using weak ciphers
- Unnecessary network services listening

## eBPF Detection Signals

### Signal 1: Debug/management ports accepting connections

**Hook**: `kprobe:tcp_connect` (inbound) or `kprobe:inet_csk_accept`

Detect when a container is accepting connections on debug ports that should not be exposed:
- 5005 (JDWP remote debugging — allows arbitrary code execution)
- 9010 (JMX — allows arbitrary MBean operations)
- 8778 (Jolokia — HTTP JMX bridge)
- 1099 (RMI registry)

**Detection logic**:
- Hook `inet_csk_accept` to see which ports are accepting connections
- Alert when connections are accepted on known debug/management ports from non-localhost sources
- Filter to container mount namespaces

**Practicality**: HIGH — listening socket detection is simple and the set of dangerous ports is well-defined.

### Signal 2: Process listening on unexpected ports

**Hook**: `tracepoint/syscalls/sys_enter_bind` or `tracepoint/syscalls/sys_enter_listen`

A misconfigured container may bind to ports it shouldn't. Track which ports each container binds to and listen on.

**Detection logic**:
- Record bind/listen events per container
- Compare against expected port set
- Alert on unexpected ports (especially 0.0.0.0 binds to debug ports)

**Practicality**: HIGH — straightforward syscall tracing.

### Signal 3: Sensitive file access (private keys, configs)

**Hook**: `tracepoint/syscalls/sys_enter_openat`

Track access to known sensitive files within the container:
- Private keys: `*.pem`, `*.key`, `id_rsa`
- Config files with credentials: `application.yml`, `application.properties`
- Kubernetes secrets: `/var/run/secrets/kubernetes.io/`

**Detection logic**:
- Match filename patterns on `openat` calls
- Alert when accessed by unexpected processes (e.g., not the main `java` PID)

**Practicality**: HIGH — file access monitoring is well-suited to eBPF.

## Assessment

**eBPF detection feasibility: HIGH**

Security misconfigurations manifest as observable system behaviours: exposed ports, unexpected listeners, sensitive file access. eBPF excels at monitoring these without modifying the application. The debug port detection alone (JDWP/JMX exposed externally) would prevent a significant class of attacks.
