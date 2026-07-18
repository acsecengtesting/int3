import java.net.URL;
import java.net.URLClassLoader;
import java.io.File;
import java.lang.reflect.Method;

public class JarLoadTest {
    public static void main(String[] args) throws Exception {
        System.out.println("JarLoadTest PID: " + ProcessHandle.current().pid());
        System.out.println("Waiting 3s for probe attachment...");
        Thread.sleep(3000);

        // Load a class from an external jar
        String jarPath = "/root/jclass_monitor/testplugin.jar";
        System.out.println("Loading class from jar: " + jarPath);

        File jarFile = new File(jarPath);
        URL[] urls = { jarFile.toURI().toURL() };
        URLClassLoader ucl = new URLClassLoader(urls, ClassLoader.getSystemClassLoader());

        Class<?> clazz = ucl.loadClass("com.example.HelloPlugin");
        System.out.println("Loaded: " + clazz.getName() + " from " + clazz.getProtectionDomain().getCodeSource().getLocation());

        // Invoke it
        Object instance = clazz.getDeclaredConstructor().newInstance();
        Method run = clazz.getMethod("run");
        run.invoke(instance);

        // Also load a JNI-heavy class to trigger native library loading
        System.out.println("\nTriggering native library loads...");
        Class.forName("java.util.zip.ZipFile");
        Class.forName("sun.security.provider.NativeSeedGenerator");

        Thread.sleep(2000);
        System.out.println("Done.");
        ucl.close();
    }
}
