import java.net.URL;
import java.net.URLClassLoader;
import java.io.File;

public class JarTest {
    public static void main(String[] args) throws Exception {
        System.out.println("JarTest PID: " + ProcessHandle.current().pid());
        System.out.println("Waiting 3s for probe attachment...");
        Thread.sleep(3000);

        // Load from JDK modules
        System.out.println("Loading classes from JDK...");
        Class.forName("javax.crypto.Cipher");
        Class.forName("javax.xml.parsers.DocumentBuilder");
        Class.forName("java.sql.Connection");

        // Dynamic URLClassLoader from a custom path
        System.out.println("Loading from URLClassLoader...");
        File jarDir = new File("/tmp");
        URL[] urls = { jarDir.toURI().toURL() };
        URLClassLoader ucl = new URLClassLoader(urls, null);
        try {
            ucl.loadClass("com.evil.Backdoor");
        } catch (ClassNotFoundException e) {
            System.out.println("Expected: " + e.getMessage());
        }

        Thread.sleep(2000);
        System.out.println("Done.");
    }
}
