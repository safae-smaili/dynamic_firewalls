import java.util.Objects;
import java.util.concurrent.TimeUnit;
public class Rule {
    PortRange portRange;
    OctetRange ipRange;
    private int matchCount = 0;
    private long lastUsedTimestamp = System.currentTimeMillis();

    public Rule(PortRange portRange, OctetRange ipRange) {
        this.portRange = portRange;
        this.ipRange = ipRange;
    }
    //tracking the last use of a rule 
    public boolean matches(int port, String ip) {
        boolean matched = portRange.contains(port) && ipRange.contains(ip);
        if (matched) {
            matchCount++;
            lastUsedTimestamp = System.currentTimeMillis();
            
        }
        return matched;
    }
//before
//    public boolean matches(int port, String ip) {
//        return portRange.contains(port) && ipRange.contains(ip);
//    }
    
    //if not being used for more then 5min (just for test) we reset the contount of use to 0
    public void decayUsage() {
        // Example: reset matchCount if not used for 1 day
        long now = System.currentTimeMillis();
        
        if (now - lastUsedTimestamp > TimeUnit.MINUTES.toMillis(10)) {
            matchCount = 0;
        }
    }
    
    public boolean isObsolete(long thresholdMillis) {
        long now = System.currentTimeMillis();
        return (now - lastUsedTimestamp) > thresholdMillis && matchCount == 0;
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Rule rule = (Rule) o;
        return portRange.equals(rule.portRange) && ipRange.equals(rule.ipRange);
    }

    @Override
    public int hashCode() {
        return Objects.hash(portRange, ipRange);
    }
    @Override
    public String toString() {
        return "Rule{" +
                "portRange=" + portRange +
                ", ipRange=" + ipRange +
                ", matchCount=" + matchCount +
                '}';
    }

}