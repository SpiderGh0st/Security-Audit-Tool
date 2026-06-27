import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import javax.management.MBeanServerConnection;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXConnectorFactory;
import javax.management.remote.JMXServiceURL;

public final class JmxReadOnlyProbe {
    private static String encode(String value) {
        return Base64.getEncoder().encodeToString(
            value.getBytes(StandardCharsets.UTF_8)
        );
    }

    private static String messages(Throwable error) {
        StringBuilder text = new StringBuilder();
        Throwable current = error;
        while (current != null) {
            if (text.length() > 0) {
                text.append(" | ");
            }
            text.append(current.getClass().getSimpleName());
            if (current.getMessage() != null) {
                text.append(": ").append(current.getMessage());
            }
            current = current.getCause();
        }
        return text.toString();
    }

    public static void main(String[] args) {
        if (args.length != 2) {
            System.out.println("RESULT\tERROR\t\t0\t0\t" +
                encode("Usage: JmxReadOnlyProbe <host> <port>"));
            System.exit(2);
        }

        String host = args[0];
        int port;
        try {
            port = Integer.parseInt(args[1]);
        } catch (NumberFormatException error) {
            System.out.println("RESULT\tERROR\t\t0\t0\t" +
                encode("Invalid port"));
            System.exit(2);
            return;
        }

        String targetHost = host.contains(":") ? "[" + host + "]" : host;
        String url = "service:jmx:rmi:///jndi/rmi://" +
            targetHost + ":" + port + "/jmxrmi";

        JMXConnector connector = null;
        try {
            connector = JMXConnectorFactory.connect(
                new JMXServiceURL(url),
                Collections.emptyMap()
            );
            MBeanServerConnection connection =
                connector.getMBeanServerConnection();

            String defaultDomain = connection.getDefaultDomain();
            String[] domains = connection.getDomains();
            Integer mbeanCount = connection.getMBeanCount();

            System.out.println(
                "RESULT\tCONNECTED\t" +
                encode(defaultDomain == null ? "" : defaultDomain) +
                "\t" + (mbeanCount == null ? 0 : mbeanCount) +
                "\t" + domains.length +
                "\t" + encode(String.join(",", domains))
            );
        } catch (SecurityException error) {
            System.out.println(
                "RESULT\tAUTH_REQUIRED\t\t0\t0\t" + encode(messages(error))
            );
        } catch (IOException error) {
            String message = messages(error);
            String lower = message.toLowerCase();
            String status = (
                lower.contains("credential") ||
                lower.contains("authentication") ||
                lower.contains("password") ||
                lower.contains("access denied") ||
                lower.contains("securityexception")
            ) ? "AUTH_REQUIRED" : "FAILED";
            System.out.println(
                "RESULT\t" + status + "\t\t0\t0\t" + encode(message)
            );
        } catch (RuntimeException error) {
            System.out.println(
                "RESULT\tFAILED\t\t0\t0\t" + encode(messages(error))
            );
        } finally {
            if (connector != null) {
                try {
                    connector.close();
                } catch (IOException ignored) {
                    // The read-only connection has already been evaluated.
                }
            }
        }
    }
}
