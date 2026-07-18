#!/bin/bash
set -e
cd /root/jclass_monitor

echo "=== Rebuilding ==="
make clean && make 2>&1 | tail -5
echo ""

# Compile exec test
cat > /tmp/ExecTest.java << 'JAVA'
public class ExecTest {
    public static void main(String[] args) throws Exception {
        System.out.println("PID: " + ProcessHandle.current().pid());
        Thread.sleep(3000);
        System.out.println("Executing 'id'...");
        Process p = Runtime.getRuntime().exec(new String[]{"id"});
        byte[] out = p.getInputStream().readAllBytes();
        p.waitFor();
        System.out.println("Result: " + new String(out).trim());
        System.out.println("Executing 'whoami'...");
        Process p2 = Runtime.getRuntime().exec(new String[]{"whoami"});
        byte[] out2 = p2.getInputStream().readAllBytes();
        p2.waitFor();
        System.out.println("Result: " + new String(out2).trim());
        System.out.println("Executing 'ls /tmp'...");
        Process p3 = Runtime.getRuntime().exec(new String[]{"ls", "/tmp"});
        byte[] out3 = p3.getInputStream().readAllBytes();
        p3.waitFor();
        System.out.println("Result: " + new String(out3).trim());
        Thread.sleep(1000);
    }
}
JAVA
javac /tmp/ExecTest.java -d /tmp/

echo "=== Running ExecTest with monitor ==="
java -cp /tmp ExecTest &
JPID=$!
echo "Java PID: $JPID"
sleep 1

echo "Attaching monitor..."
/root/jclass_monitor/jclass_monitor -v -n -p $JPID > /tmp/jclass_out.log 2>&1 &
BPID=$!

wait $JPID 2>/dev/null || true
sleep 1
kill $BPID 2>/dev/null || true
wait $BPID 2>/dev/null || true

echo ""
echo "=== MONITOR OUTPUT ==="
cat /tmp/jclass_out.log
