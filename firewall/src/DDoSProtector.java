import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class DDoSProtector {

    private final Firewall firewall;

    // Track requests per IP (IP -> count)
    private final ConcurrentHashMap<String, Integer> ipRequestCounts = new ConcurrentHashMap<>();

    // Track total requests per second
    private final AtomicInteger totalRequests = new AtomicInteger(0);

    // Blocklist for IPs exceeding thresholds (IP -> block timestamp)
    private final ConcurrentHashMap<String, Long> blockedIPs = new ConcurrentHashMap<>();

    // Configuration thresholds - adjust as needed
    private static final int MAX_REQUESTS_PER_IP_PER_MINUTE = 10 ;  // Max requests per IP per minute
    private static final int MAX_TOTAL_REQUESTS_PER_SECOND = 1000;  // Max total requests per second
    private static final long BLOCK_DURATION_MINUTES = 10;          // Block duration for offending IPs

    public DDoSProtector(Firewall firewall) {
        this.firewall = firewall;
        scheduleCleanup();
    }

    /**
     * Checks if the given IP is allowed to send packets.
     * If IP exceeds allowed request rates, removes all rules related to it and blocks it temporarily.
     *
     * @param ip IP address of the incoming packet
     * @return true if allowed, false if blocked
     */
    public boolean isAllowed(String ip) {
        long now = System.currentTimeMillis();

        // Check if IP is currently blocked
        if (blockedIPs.containsKey(ip)) {
            long blockStart = blockedIPs.get(ip);
            if (now - blockStart < TimeUnit.MINUTES.toMillis(BLOCK_DURATION_MINUTES)) {
                // Still blocked
                return false;
            } else {
                // Block expired, remove from blocklist
                blockedIPs.remove(ip);
            }
        }

        // Increment global request count
        int currentTotal = totalRequests.incrementAndGet();

        // Increment per-IP request count
        int ipCount = ipRequestCounts.merge(ip, 1, Integer::sum);

        // Check per-IP threshold
        if (ipCount > MAX_REQUESTS_PER_IP_PER_MINUTE) {
            System.out.println("DDoS detected: Blocking IP due to high request rate: " + ip);

            // Add IP to blocklist
            blockedIPs.put(ip, now);

            // Remove all firewall rules related to this IP
            firewall.removeRulesForIP(ip);

            // Persist updated rules to CSV
            firewall.exportRulesToCSV(firewall.getCsvFilePath());

            return false;
        }

        // Check global threshold
        if (currentTotal > MAX_TOTAL_REQUESTS_PER_SECOND) {
            System.out.println("DDoS detected: Global request rate exceeded. Temporarily blocking new requests.");
            return false;
        }

        return true;
    }

    /**
     * Schedule periodic cleanup to reset counters every minute.
     * This keeps the request counts fresh and allows temporary blocks to expire.
     */
    void scheduleCleanup() {
        ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
        scheduler.scheduleAtFixedRate(() -> {
            ipRequestCounts.clear();
            totalRequests.set(0);
            // Optionally, clean expired blocks here if you want more aggressive unblocking
            long now = System.currentTimeMillis();
            blockedIPs.entrySet().removeIf(entry -> now - entry.getValue() > TimeUnit.MINUTES.toMillis(BLOCK_DURATION_MINUTES));
        }, 1, 1, TimeUnit.MINUTES);
    }
}
