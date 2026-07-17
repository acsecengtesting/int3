// Simple test app that loads classes dynamically to exercise the classloader monitor
import java.net.URL;
import java.net.URLClassLoader;
import java.io.File;

public class TestApp {
    public static void main(String[] args) throws Exception {
        System.out.println("TestApp starting... PID: " + ProcessHandle.current().pid());
        System.out.println("Waiting 5 seconds for probe attachment...");
        Thread.sleep(5000);

        System.out.println("Loading standard library classes...");
        // Force some class loading
        Class.forName("java.util.HashMap");
        Class.forName("java.util.concurrent.ConcurrentHashMap");
        Class.forName("java.security.SecureRandom");

        System.out.println("Loading via reflection...");
        Class.forName("javax.crypto.Cipher");
        Class.forName("javax.net.ssl.SSLContext");

        System.out.println("Done. Sleeping for cleanup...");
        Thread.sleep(2000);
        System.out.println("Exiting.");
    }
}
