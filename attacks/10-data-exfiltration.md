# Data Exfiltration

## OWASP Classification
API3:2023 — Broken Object Property Level Authorization (excessive data exposure)
Relates to: OWASP A01 Broken Access Control

## Attack Class Description

After gaining access to data (via BOLA, SQLi, SSRF, or any other vector),
the attacker needs to get the data out of the environment. Exfiltration
techniques from containerised Java apps include:

- Bulk data sent to attacker-controlled HTTP endpoints
- DNS tunnelling (encoding data in DNS query subdomains)
- Uploading to cloud storage (S3, GCS) using stolen credentials
- Embedding data in normal-looking outbound requests
- Writing to mounted volumes that are accessible externally

## eBPF Detection Signals

### Signal 1: Unusual outbound data volume

**Hook**: `kprobe:tcp_sendmsg` or `tracepoint/sock/sock_sendmsg`

Track bytes sent per container per destination. A spike in outbound data
to a destination not seen during normal operation is a strong exfil signal.

**Detection logic**:
- Per-destination byte counter in a BPF hash map
- Alert when outbound volume to a new IP exceeds threshold
- Particularly flag large transfers to non-CDN, non-API-backend IPs

**Practicality**: HIGH — kernel can track bytes per socket efficiently.

### Signal 2: DNS tunnelling (high-entropy subdomain queries)

**Hook**: XDP/TC or kprobe on UDP sendmsg to port 53

Data encoded in DNS queries appears as long, high-entropy subdomains:
`aGVsbG8gd29ybGQ.data.attacker.com`

**Detection logic**:
- Capture DNS query names from containers
- Alert when subdomain length exceeds threshold (>30 chars)
- Alert when query rate to a single domain is abnormally high
- Check for base64/hex character patterns in subdomains

**Practicality**: HIGH — already have DNS monitoring infrastructure.
Can add entropy/length checks to the existing DNS monitor.

### Signal 3: Connections to cloud storage endpoints

**Hook**: `kprobe:tcp_connect`

Exfiltration to cloud storage uses connections to S3/GCS/Azure endpoints.
If the container's role doesn't include storage access, these connections
are suspicious.

**Detection logic**:
- DNS lookups for `*.s3.amazonaws.com`, `storage.googleapis.com`,
  `*.blob.core.windows.net`
- TCP connections to IPs resolving to these services
- Alert when not in the container's expected access pattern

**Practicality**: MEDIUM — requires knowing what the app should access.

### Signal 4: Large file writes to shared volumes

**Hook**: `tracepoint/syscalls/sys_enter_write` on specific fds,
or `tracepoint/block/block_rq_issue`

If the container writes large amounts of data to a mounted volume
(PVC, hostPath), it could be staging for exfil.

**Detection logic**:
- Track write volume to mounted paths per container
- Alert on sudden large writes to shared/external volumes

**Practicality**: MEDIUM — requires identifying shared mount points.

## Assessment

**eBPF detection feasibility: HIGH**

Data exfiltration produces clear network and I/O signals. The strongest
detections are outbound volume anomalies and DNS tunnelling patterns,
both well-suited to eBPF. Combined with connection tracking (unexpected
destinations), eBPF provides robust exfiltration detection without
needing to decrypt TLS.

## eBPF Detection Signals

### Signal 1: Unusual outbound data volume

**Hook**: `kprobe:tcp_sendmsg` or `tracepoint/sock/sock_sendmsg`

Track bytes sent per container per destination. A spike in outbound data to a destination not seen during normal operation is a strong exfil signal.

**Detection logic**:
- Per-destination byte counter in a BPF hash map
- Alert when outbound volume to a new IP exceeds threshold
- Particularly flag large transfers to non-CDN, non-API-backend IPs

**Practicality**: HIGH — kernel can track bytes per socket efficiently.

### Signal 2: DNS tunnelling (high-entropy subdomain queries)

**Hook**: XDP/TC or kprobe on UDP sendmsg to port 53

Data encoded in DNS queries appears as long, high-entropy subdomains: `aGVsbG8gd29ybGQ.data.attacker.com`

**Detection logic**:
- Capture DNS query names from containers
- Alert when subdomain length exceeds threshold (>30 chars)
- Alert when query rate to a single domain is abnormally high
- Check for base64/hex character patterns in subdomains

**Practicality**: HIGH — already have DNS monitoring infrastructure.

### Signal 3: Connections to unexpected cloud storage endpoints

**Hook**: `kprobe:tcp_connect` + DNS monitoring

Exfiltration to cloud storage uses connections to S3/GCS/Azure endpoints. If the container's role doesn't include storage access, these connections are suspicious.

**Detection logic**:
- DNS lookups for `*.s3.amazonaws.com`, `storage.googleapis.com`, `*.blob.core.windows.net`
- Alert when not in the container's expected access pattern

**Practicality**: MEDIUM — requires baseline of expected behaviour.

### Signal 4: Large outbound transfer in a single connection

**Hook**: `kprobe:tcp_sendmsg`

A single TCP connection sending >10MB from an API container that normally sends small JSON responses is anomalous.

**Detection logic**:
- Track cumulative bytes per socket
- Alert when a single socket exceeds a payload threshold

**Practicality**: HIGH — straightforward per-socket byte counting.

## Assessment

**eBPF detection feasibility: HIGH**

Data exfiltration produces clear network signals. Outbound volume anomalies and DNS tunnelling patterns are well-suited to eBPF. Combined with connection tracking (unexpected destinations), eBPF provides robust exfiltration detection without needing to decrypt TLS content.
