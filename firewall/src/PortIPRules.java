//import java.util.Set;
//import java.util.HashSet;
//import java.util.TreeSet;
//
//public class PortIPRules {
//
//    Set<Integer> portSet;
//    Set<String> IPSet;
//
//    // using a TreeSet for storing ranges to allow O(log n) lookups - uses compareTo to maintain sorted order
//    TreeSet<PortRange> portRanges;
//    TreeSet<OctetRange> IPRanges;
//
//    public PortIPRules() {
//        portSet = new HashSet<>(); IPSet = new HashSet<>();
//        portRanges = new TreeSet<>(); IPRanges = new TreeSet<>();
//    }
//
//    public void addIPRule(String IP) {
//        if (IP.contains("-")) { // range
//            String[] split = IP.split("-");
//            IPRanges.add(new OctetRange(split[0], split[1]));
//            System.out.println("a range is created");
//            System.out.println(IP.contains("-"));
//        } else
//            IPSet.add(IP);
//    }
//
//    public void addPortRule(String port) {
//        if (port.contains("-")) { // range
//            String[] split = port.split("-");
//            portRanges.add(new PortRange(split[0], split[1]));
//        } else
//            portSet.add(Integer.parseInt(port));
//    }
//
//    public boolean match(String port, String IP) {
//        return matchPort(port) && matchIP(IP);
//    }
//
//    private boolean matchPort(String port) {
//        if (portSet.contains(Integer.parseInt(port)))
//            return true;
//        PortRange range = new PortRange(port, port);
//        if (portRanges.contains(range)) // start boundary match
//            return true;
//        boolean flag = false;
//        PortRange lower = portRanges.lower(range);
//        if (lower != null)
//            flag = lower.end >= range.start; // falls within end of left range
//        return flag;
//    }
//
//    private boolean matchIP(String IP) {
//        if (IPSet.contains(IP))
//            return true;
//        OctetRange range = new OctetRange(IP, IP);
//        if (IPRanges.contains(range)) // start boundary match
//            return true;
//        boolean flag = false;
//        OctetRange lower = IPRanges.lower(range);
//        if (lower != null)
//            flag = lower.endIP >= range.startIP; // falls within end of left range
//        return flag;
//    }
//}





import java.util.ArrayList;
import java.util.List;

import java.util.Iterator;

public class PortIPRules {
    List<Rule> rules;

    public PortIPRules() {
        rules = new ArrayList<>();
    }
    public List<Rule> getRules() {
        return new ArrayList<>(rules);
    }
    public synchronized void removeRule(Rule rule) {
        rules.remove(rule);
    }


    public void addRule(String portStr, String ipStr) {
        PortRange portRange;
        if (portStr.contains("-")) {
            String[] parts = portStr.split("-");
            portRange = new PortRange(parts[0], parts[1]);
        } else {
            portRange = new PortRange(portStr, portStr);
        }

        OctetRange ipRange;
        if (ipStr.contains("-")) {
            String[] parts = ipStr.split("-");
            ipRange = new OctetRange(parts[0], parts[1]);
        } else {
            ipRange = new OctetRange(ipStr, ipStr);
        }
        Rule r=new Rule(portRange,ipRange);
        rules.add(new Rule(portRange, ipRange));
        System.out.println("Added rule: " +r);
        
    }
//remove anciennes rules qui no sont pas utuliser pour un ovsoletethresholdmillis qui est chanchable
    public synchronized void removeObsoleteRules(long obsoleteThresholdMillis) {
        Iterator<Rule> iterator = rules.iterator();
        while (iterator.hasNext()) {
            Rule rule = iterator.next();
            rule.decayUsage();
            if (rule.isObsolete(obsoleteThresholdMillis)) {
                System.out.println("Removing obsolete rule: " + rule);
                iterator.remove();
            }
        }
    }

    public boolean match(String portStr, String ipStr) {
        int port = Integer.parseInt(portStr);
        for (Rule rule : rules) {
            if (rule.matches(port, ipStr)) {
            	rule.toString();
                return true;
            }
        }
        return false;
    }
    
    //related to ddos attacks to delete rules by ip addresses 
    public synchronized void removeRulesByIP(String ipToRemove) {
        Iterator<Rule> iterator = rules.iterator();
        while (iterator.hasNext()) {
            Rule rule = iterator.next();
            if (rule.ipRange.contains(ipToRemove)) {
                System.out.println("Removing rule due to DDoS IP block: " + rule);
                iterator.remove();
            }
        }
    }
}



