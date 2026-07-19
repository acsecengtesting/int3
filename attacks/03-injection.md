# Injection (SQL, Command, LDAP, Expression Language)

## OWASP Classification
OWASP Top 10 2025: A03 (Injection) / API Security: relates to API8 (Security Misconfiguration)

## Attack Class Description

Attacker-supplied data is sent to an interpreter (SQL engine, OS shell, LDAP directory, expression language evaluator) without proper validation or escaping. This leads to execution of unintended commands or queries.

In Java containers, common variants include:
- **SQL injection** via JDBC with string concatenation
- **OS command injection** via `Runtime.exec()` or `ProcessBuilder`
- **LDAP injection** via Spring LDAP or JNDI
- **Expression Language injection** (Spring EL, OGNL in Struts)

## eBPF Detection Signals

### Signal 1: Process execution from a web application container

**Hook**: `tracepoint/syscalls/sys_enter_execve`

Java web applications should NEVER spawn child processes in normal operation. Any `execve` from a JVM PID inside a container is a strong signal of command injection.

**Detection logic**:
- Filter by container mount namespace
- Filter by parent PID being a `java` process
- Alert with the command and arguments

**Practicality**: HIGH — this is exactly what our existing `sys_enter_execve` tracepoint does. A Java API container calling `/bin/sh`, `curl`, `wget`, `nc`, etc. is almost always an attack.

### Signal 2: Unusual outbound connections following command injection

**Hook**: `kprobe:tcp_connect`

After successful injection, attackers typically:
- Download tools via `wget`/`curl` (outbound HTTP to unusual IPs)
- Establish reverse shells (outbound to high ports on attacker IPs)
- Exfiltrate data (outbound to cloud storage endpoints)

**Detection logic**:
- Track outbound connections from container PIDs
- Alert on connections to unusual ports (not 80/443 or configured service ports)
- Alert on connections to RFC1918 link-local metadata IPs (169.254.169.254)

**Practicality**: HIGH — containerised Java APIs have predictable network patterns. Any deviation is detectable.

### Signal 3: DNS lookups for unusual domains

**Hook**: XDP/TC or `kprobe:udp_sendmsg` to port 53

Post-injection, the attacker's tools resolve domains not seen during normal operation. DNS-based exfiltration (encoding data in DNS queries) is also common.

**Detection logic**:
- Track DNS queries from container PIDs
- Alert on first-seen domains, particularly those with high entropy subdomains
- Alert on TXT record queries (often used for C2)

**Practicality**: HIGH — our DNS monitor already captures this.

### Signal 4: File writes to unexpected locations

**Hook**: `kprobe:ovl_open` (with write intent) or `tracepoint/syscalls/sys_enter_openat` with O_WRONLY/O_CREAT

Command injection often drops files (webshells, tools, scripts) into the container's writable layer.

**Detection logic**:
- Our overlay detector already catches this for `.so`, `.class`, `.jar`
- Extend to catch writes of `.sh`, `.py`, binaries, or any file in `/tmp`, `/dev/shm`

**Practicality**: HIGH — directly observable at the kernel level.

## Assessment

**eBPF detection feasibility: HIGH**

Command injection is one of the most detectable attack classes from eBPF. The post-exploitation signals (process spawn, outbound connections, file writes, DNS) are all strongly observable and have low false-positive rates in containerised Java applications that should not be spawning processes or making unexpected network connections.
