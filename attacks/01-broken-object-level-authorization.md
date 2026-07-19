# Broken Object Level Authorization (BOLA)

## OWASP Classification
API1:2023 — Broken Object Level Authorization

## Attack Class Description

The API exposes endpoints accepting object identifiers (IDs) from the client. The server fails to verify that the authenticated user is authorized to access the requested object. Attackers enumerate or guess IDs to access other users' data.

Example: `GET /api/users/1234/orders` — attacker changes 1234 to 1235 and retrieves another user's orders.

## Why it matters in containers

Java API servers (Spring Boot, Jakarta EE, Quarkus) running in containers handle many requests concurrently. BOLA is the most common API vulnerability and leads directly to data breaches.

## eBPF Detection Signals

### Signal 1: Abnormal data access volume per authenticated session

**Hook**: `kprobe:tcp_sendmsg` or `tracepoint/syscalls/sys_exit_read`

A BOLA exploit typically involves rapid sequential requests with incrementing IDs. From eBPF we can observe:
- Response payload sizes per connection (large volumes of data being sent out from the API container)
- Rate of outbound data per source socket

**Practicality**: LOW — eBPF sees raw bytes, not API semantics. Cannot distinguish legitimate pagination from BOLA enumeration without application context.

### Signal 2: Unusual syscall patterns indicating enumeration

**Hook**: `kprobe:tcp_recvmsg` / `kprobe:tcp_sendmsg`

Rapid sequential request/response cycles from the same source to the same endpoint — high frequency of small inbound reads followed by varying-size outbound writes.

**Practicality**: LOW — too generic at the kernel level. Network rate limiting is better handled at the application or reverse proxy layer.

### Signal 3: Database query volume anomaly (if detectable)

**Hook**: `uprobe` on database driver native methods or `kprobe:tcp_connect` to database ports

If the Java app connects to a database, rapid queries from the same PID (more queries per unit time than typical) could indicate enumeration.

**Practicality**: MEDIUM — correlating network activity to the database port (e.g., 5432 for PostgreSQL) with request volume is feasible but requires baseline knowledge.

## Assessment

**eBPF detection feasibility: LOW**

BOLA is fundamentally an application-logic vulnerability. The kernel sees network traffic but cannot interpret authorization semantics. eBPF is not the right tool for this class — it requires application-level instrumentation (API gateway rate limiting, access logs, or a service mesh with authorization policy enforcement).

eBPF's role here is limited to supporting evidence: anomalous data volumes, unusual database query rates, or outbound data exfiltration patterns that follow a BOLA exploit.
