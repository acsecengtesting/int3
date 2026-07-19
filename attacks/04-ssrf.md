# Server-Side Request Forgery (SSRF)

## OWASP Classification
API7:2023 — Server Side Request Forgery / OWASP Top 10 2025: folded into A01

## Attack Class Description

The application fetches a remote resource using a URL supplied by the user without proper validation. The attacker coerces the server to make requests to:
- Internal services (bypassing firewalls)
- Cloud metadata endpoints (169.254.169.254) to steal IAM credentials
- Other containers in the same network namespace
- Localhost services not exposed externally

In Java: common in image fetchers, webhook senders, PDF generators, URL preview features, and any endpoint that accepts a URL parameter.

## eBPF Detection Signals

### Signal 1: Connection to cloud metadata endpoint (169.254.169.254)

**Hook**: `kprobe:tcp_connect` or `tracepoint/syscalls/sys_enter_connect`

The single most impactful SSRF target in cloud environments. A Java web app container should NEVER connect to 169.254.169.254.

**Detection logic**:
- Check destination IP == 169.254.169.254 (or IPv6 equivalent)
- Filter to container mount namespaces
- Immediate critical alert

**Practicality**: VERY HIGH — trivial to implement, zero false positives for containerised Java web apps. The link-local metadata IP is never a legitimate destination from application code.

### Signal 2: Connection to RFC1918 internal addresses from a public-facing container

**Hook**: `kprobe:tcp_connect`

SSRF to internal services uses addresses like 10.x.x.x, 172.16-31.x.x, 192.168.x.x. If the container normally only connects to specific known backends, any connection to an unexpected internal address is suspicious.

**Detection logic**:
- Maintain a map of "expected" destination IPs/ports per container (populated at startup by observing normal traffic for a learning period)
- Alert on connections to internal IPs not in the expected set
- Particularly flag connections to common internal service ports (6379/Redis, 5432/Postgres, 9200/Elasticsearch) that are not the container's configured backend

**Practicality**: HIGH — requires a baselining phase but the detection is purely network-level, well-suited to eBPF.

### Signal 3: Connection to localhost (127.0.0.1) on unexpected ports

**Hook**: `kprobe:tcp_connect`

SSRF to localhost targets services running on the same host/pod. A Java web app connecting to random localhost ports is abnormal.

**Detection logic**:
- Track connect() to 127.0.0.1 / ::1 where destination port is not an expected service
- Java apps legitimately connect to localhost for JMX (typically port 9010) or debug — these can be allowlisted

**Practicality**: HIGH — clear signal with easy allowlisting.

### Signal 4: Outbound connections to many distinct IPs in a short window

**Hook**: `kprobe:tcp_connect`

SSRF scanning/enumeration results in the app connecting to many different internal IPs. Normal app behaviour connects to a fixed set of backends.

**Detection logic**:
- Count distinct destination IPs per container per time window
- Alert when the count exceeds a threshold (e.g., >10 distinct IPs in 60 seconds from a single container)

**Practicality**: HIGH — fan-out detection is simple counting in a BPF hash map.

## Assessment

**eBPF detection feasibility: VERY HIGH**

SSRF is one of the best-suited attack classes for eBPF detection. The core signal — outbound connections to unexpected destinations — is directly observable at the `tcp_connect` level. The metadata endpoint check (169.254.169.254) alone would have prevented the Capital One breach.
