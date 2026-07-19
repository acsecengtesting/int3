# Software Supply Chain and Data Integrity Failures

## OWASP Classification
OWASP Top 10 2025: A03 — Software Supply Chain Failures
API10:2023 — Unsafe Consumption of APIs

## Attack Class Description

The application loads and executes code or data from sources it should not trust:
- **Malicious dependencies**: a compromised library in the build (typosquatting, dependency confusion)
- **Runtime class injection**: loading classes from untrusted sources at runtime (JNDI injection, remote classloaders)
- **Dynamic code loading**: `URLClassLoader` fetching bytecode from attacker-controlled URLs
- **Class shadowing**: a malicious class with the same fully-qualified name overrides a legitimate one based on classpath ordering

## eBPF Detection Signals

### Signal 1: Class loaded from unexpected source

**Hook**: `uprobe:JVM_DefineClassWithSource`

The `source` parameter reveals where the class bytes came from. Any source that is not the application jar, JDK modules (`jrt:/`), or a known dependency jar is suspicious.

**Detection logic**:
- Alert on `source` containing `http://`, `https://`, `ftp://`, `ldap://`
- Alert on `source` containing paths outside the expected deployment directory
- Classes with no source (null) loaded after startup phase

**Practicality**: HIGH — already implemented in our classloader monitor.

### Signal 2: Class/jar/so loaded from writable overlay layer

**Hook**: `kprobe:ovl_open`

If a class, jar, or native library is being loaded from the container's writable layer, it was NOT part of the original image.

**Detection logic**:
- Check `ovl_inode.__upperdentry != NULL` for `.class`, `.jar`, `.so` files
- Filter to container mount namespaces

**Practicality**: VERY HIGH — already implemented and tested in `ovl_detect`.

### Signal 3: Outbound connection to download code at runtime

**Hook**: `kprobe:tcp_connect`

A supply chain attack that fetches code at runtime (like Log4Shell's JNDI or a compromised library phoning home) will make outbound connections not seen during normal operation.

**Detection logic**:
- Track outbound connections from the JVM process
- Alert on connections to IPs/ports not seen during a baseline period
- Particularly flag connections to non-standard ports or unusual destinations that occur during class loading activity

**Practicality**: HIGH — straightforward network monitoring.

### Signal 4: Native library loaded from outside expected paths

**Hook**: `uprobe:JVM_LoadLibrary`

JNI libraries should only come from the JDK or the application's own lib directory. A library loaded from `/tmp`, `/dev/shm`, or any writable path is suspicious.

**Detection logic**:
- Check library path prefix against expected directories
- Alert on paths in `/tmp`, `/var/tmp`, `/dev/shm`, or user-writable locations

**Practicality**: HIGH — already implemented in the classloader monitor.

## Assessment

**eBPF detection feasibility: VERY HIGH**

Supply chain and integrity attacks are among the best-detected classes from eBPF. The core behaviours — loading code from unexpected sources, downloading code at runtime, executing code from writable layers — are all directly observable at the kernel level. This is where our detectors (`ovl_detect`, `jclass_monitor`, `jni_net`) excel.
