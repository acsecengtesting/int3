# Broken Authentication

## OWASP Classification
API2:2023 — Broken Authentication

## Attack Class Description

Authentication mechanisms are implemented incorrectly, allowing attackers to compromise tokens, brute-force credentials, or exploit implementation flaws to assume other users' identities. This includes weak JWT validation, credential stuffing, token replay, and session fixation.

## Why it matters in containers

Containerised Java APIs often use JWT tokens validated locally. A compromised authentication flow means all downstream services trust a forged identity.

## eBPF Detection Signals

### Signal 1: Brute-force login attempts (high connection rate)

**Hook**: `kprobe:tcp_connect` / `tracepoint/syscalls/sys_enter_connect`

From a single source IP, rapid TCP connections to the authentication endpoint. eBPF can track:
- Connection count per source IP per time window
- Connections to specific destination ports (e.g., 8080/443)

**Practicality**: MEDIUM — eBPF can count connections per-source at the kernel level efficiently. However, it cannot distinguish login endpoint from other endpoints without parsing HTTP.

### Signal 2: Credential stuffing via outbound connection to known-bad IPs

**Hook**: `kprobe:tcp_connect`

If an attacker achieves RCE via compromised credentials and then pivots (connects outbound to C2), eBPF catches the anomalous outbound connection from the container.

**Practicality**: HIGH — unusual outbound connections from a container that normally only accepts inbound traffic is a strong post-compromise signal.

### Signal 3: Token file/secret access from unexpected processes

**Hook**: `tracepoint/syscalls/sys_enter_openat`

If the JVM stores tokens, keys, or secrets on disk (e.g., mounted Kubernetes secrets), eBPF can monitor which processes access those files. An unexpected PID or `comm` reading `/var/run/secrets/` is suspicious.

**Practicality**: HIGH — file access monitoring for sensitive paths is well-suited to eBPF and has low false positive rates when paths are clearly defined.

## Assessment

**eBPF detection feasibility: MEDIUM**

The authentication flow itself is application-level (HTTP headers, JWT parsing), which eBPF cannot inspect without TLS decryption. However, the consequences of broken authentication — anomalous access patterns, secret file reads, and post-compromise pivoting — are observable at the kernel level.
