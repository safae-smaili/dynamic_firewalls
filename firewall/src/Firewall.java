import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.io.FileNotFoundException;
import java.util.concurrent.Executors;
//import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
//import org.junit.Assert;

public class Firewall {
	private final DDoSProtector ddosProtector;
	 private static final long OBSOLETE_THRESHOLD_MILLIS = TimeUnit.MINUTES.toMillis(5);
	 private final String csvFilePath;
    final PortIPRules inTCP = new PortIPRules();
    final PortIPRules inUDP = new PortIPRules();
    final PortIPRules outTCP = new PortIPRules();
    final PortIPRules outUDP = new PortIPRules();

    // selection[x][y]: x - direction, y - protocol
    // x = 0 - inbound, 1 - outbound
    // y = 0 - TCP, 1 - UDP
    final PortIPRules[][] selection = new PortIPRules[2][2];

    public Firewall(String filename) {
    	this.csvFilePath = filename;
    	
    	 
        selection[0][0] = inTCP; selection[0][1] = inUDP;
        selection[1][0] = outTCP; selection[1][1] = outUDP;

        try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
            String line;
            while ((line = br.readLine()) != null) {
            	 //System.out.println(line);
            	//System.out.println(br.readLine() != null);
            	
                String[] rule = line.split(",");
                if (rule.length < 4) {
                    System.err.println("Skipping invalid rule line (expected 4 fields): " + line);
                    continue; // skip this line and continue to next
                }

                //System.out.print(rule[3]+"\n");
                int direction = rule[0].equals("inbound")? 0 : 1;
                
                int protocol = rule[1].equals("tcp")? 0 : 1;
                
                
                PortIPRules ruleSet = selection[direction][protocol];
                
                //System.out.print(selection[direction][protocol] +" this is the ruleset1\n");
               
                //changes
                //ruleSet.addPortRule(rule[2]);
                //ruleSet.addIPRule(rule[3]);
                ruleSet.addRule(rule[2], rule[3]);
            } //System.out.println(line);
        } catch (FileNotFoundException fe) {
            System.out.println(filename + "not found");
        } catch (Exception e) {
            e.printStackTrace();
        }
        this.ddosProtector = new DDoSProtector(this);
        ddosProtector.scheduleCleanup();
    }
    //recrire les rules on csv file:
    public synchronized void exportRulesToCSV(String filename) {
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(filename))) {
            for (int dir = 0; dir < 2; dir++) {
                for (int pro = 0; pro < 2; pro++) {
                    PortIPRules ruleSet = selection[dir][pro];
                    String direction = (dir == 0) ? "inbound" : "outbound";
                    String protocol = (pro == 0) ? "tcp" : "udp";
                    for (Rule rule : ruleSet.getRules()) {
                        String portStr = rule.portRange.start == rule.portRange.end ?
                            String.valueOf(rule.portRange.start) :
                            rule.portRange.start + "-" + rule.portRange.end;
                        String ipStr = rule.ipRange.startIP.equals(rule.ipRange.endIP) ?
                            rule.ipRange.startA + "." + rule.ipRange.startB + "." + rule.ipRange.startC + "." + rule.ipRange.startD :
                            rule.ipRange.startA + "." + rule.ipRange.startB + "." + rule.ipRange.startC + "." + rule.ipRange.startD +
                            "-" + rule.ipRange.endA + "." + rule.ipRange.endB + "." + rule.ipRange.endC + "." + rule.ipRange.endD;

                        bw.write(String.join(",", direction, protocol, portStr, ipStr));
                        bw.newLine();
                    }
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    //removing old rules 
    public synchronized void removeObsoleteRules(String filepath) {
        inTCP.removeObsoleteRules(OBSOLETE_THRESHOLD_MILLIS);
        inUDP.removeObsoleteRules(OBSOLETE_THRESHOLD_MILLIS);
        outTCP.removeObsoleteRules(OBSOLETE_THRESHOLD_MILLIS);
        outUDP.removeObsoleteRules(OBSOLETE_THRESHOLD_MILLIS);
        
        exportRulesToCSV(filepath);
    }
    
    //new
    public Set<RuleWrapper> loadRulesFromCSV(String filename) {
        Set<RuleWrapper> rules = new HashSet<>();
        try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] parts = line.split(",");
                if (parts.length < 4) continue;
                String direction = parts[0].trim();
                String protocol = parts[1].trim();
                String port = parts[2].trim();
                String ip = parts[3].trim();

                PortRange portRange;
                if (port.contains("-")) {
                    String[] pr = port.split("-");
                    portRange = new PortRange(pr[0], pr[1]);
                } else {
                    portRange = new PortRange(port, port);
                }

                OctetRange ipRange;
                if (ip.contains("-")) {
                    String[] ipr = ip.split("-");
                    ipRange = new OctetRange(ipr[0], ipr[1]);
                } else {
                    ipRange = new OctetRange(ip, ip);
                }

                Rule rule = new Rule(portRange, ipRange);
                rules.add(new RuleWrapper(direction, protocol, rule));
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return rules;
    }

    
    
    
    
    
    
    //new 
    public void updateRulesFromCSV(String filename) {
        Set<RuleWrapper> newRules = loadRulesFromCSV(filename);
        Set<RuleWrapper> currentRules = new HashSet<>();

        // Get current rules with direction and protocol info
        for (int dir = 0; dir < 2; dir++) {
            for (int pro = 0; pro < 2; pro++) {
                String direction = (dir == 0) ? "inbound" : "outbound";
                String protocol = (pro == 0) ? "tcp" : "udp";
                for (Rule r : selection[dir][pro].getRules()) {
                    currentRules.add(new RuleWrapper(direction, protocol, r));
                }
            }
        }

        // Find rules to add
        Set<RuleWrapper> toAdd = new HashSet<>(newRules);
        toAdd.removeAll(currentRules);

        // Find rules to remove
        Set<RuleWrapper> toRemove = new HashSet<>(currentRules);
        toRemove.removeAll(newRules);

        // Apply removals
        for (RuleWrapper rw : toRemove) {
            removeRule(rw.direction, rw.protocol, rw.rule);
        }

        // Apply additions
        for (RuleWrapper rw : toAdd) {
            addRule(rw.direction, rw.protocol, rw.rule.portRange.start + (rw.rule.portRange.start != rw.rule.portRange.end ? "-" + rw.rule.portRange.end : ""), 
                    rw.rule.ipRange.startA + "." + rw.rule.ipRange.startB + "." + rw.rule.ipRange.startC + "." + rw.rule.ipRange.startD +
                    (rw.rule.ipRange.startIP.equals(rw.rule.ipRange.endIP) ? "" : "-" + rw.rule.ipRange.endA + "." + rw.rule.ipRange.endB + "." + rw.rule.ipRange.endC + "." + rw.rule.ipRange.endD));
        }
    }
    
    
    //for ddos
    public String getCsvFilePath() {
		return csvFilePath;
	}
    
    
    
    

    public synchronized List<Rule> getAllRules() {
        List<Rule> all = new ArrayList<>();
        all.addAll(inTCP.getRules());
        all.addAll(inUDP.getRules());
        all.addAll(outTCP.getRules());
        all.addAll(outUDP.getRules());
        return all;
    }

    public synchronized void addRule(String direction, String protocol, String portStr, String ipStr) {
        int dir = direction.equals("inbound") ? 0 : 1;
        int pro = protocol.equals("tcp") ? 0 : 1;
        selection[dir][pro].addRule(portStr, ipStr);
    }

    public synchronized void removeRule(String direction, String protocol, Rule rule) {
        int dir = direction.equals("inbound") ? 0 : 1;
        int pro = protocol.equals("tcp") ? 0 : 1;
        selection[dir][pro].removeRule(rule);
    }


    public boolean accept_packet(String direction, String protocol, int port, String ip_address) {
        int dir = direction.equals("inbound")? 0 : 1;
        int pro = protocol.equals("tcp")? 0 : 1;
        
        PortIPRules ruleSet = selection[dir][pro];
        if (!ddosProtector.isAllowed(ip_address)) {
            System.out.println("Packet blocked by DDoS protector: " + ip_address);
            return false;
        }
        //System.out.print(selection[dir][pro] +" this is the ruleset\n");
        return ruleSet.match(String.valueOf(port), ip_address);
    }


    public void startAutoUpdate(String csvFilePath) {
        Executors.newSingleThreadScheduledExecutor().scheduleAtFixedRate(() -> {
            updateRulesFromCSV(csvFilePath);
        }, 0, 1, TimeUnit.MINUTES);
    }

    //ddos related
    public synchronized void removeRulesForIP(String ip) {
        inTCP.removeRulesByIP(ip);
        inUDP.removeRulesByIP(ip);
        outTCP.removeRulesByIP(ip);
        outUDP.removeRulesByIP(ip);
    }
    
    
    
    public static void main(String[] args) throws InterruptedException {
    	Firewall firewall = new Firewall("C:\\Users\\ASUS\\git\\firewall\\src\\rules.csv");
//    	
//    	boolean allowed = firewall.accept_packet("inbound", "tcp",80, "192.168.1.3");
//    	firewall.accept_packet("inbound", "tcp",80, "192.168.1.2");
//    	firewall.accept_packet("outbound", "udp",1001, "52.12.48.92");
//    	
//    	if (allowed) {
//    	    System.out.println("Packet accepted");
//    	} else {
//    	    System.out.println("Packet rejected");
//    	}
//    	firewall.startAutoUpdate("C:\\Users\\ASUS\\git\\firewall\\src\\rules.csv");
//    	Thread.sleep(160000);
//    	 allowed = firewall.accept_packet("inbound", "tcp",80, "192.168.1.3");
//    	 //firewall.accept_packet("inbound", "tcp",80, "192.168.1.2");
//     	//firewall.accept_packet("outbound", "udp",1001, "52.12.48.92");
//    	 
//    		if (allowed) {
//        	    System.out.println("Packet accepted");
//        	} else {
//        	    System.out.println("Packet rejected2");
//        	}
//    		ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2);
//            // Run every 2 m
//            scheduler.scheduleAtFixedRate(() -> {
//                System.out.println("Running scheduled obsolete rule cleanup...");
//                firewall.removeObsoleteRules("C:\\Users\\ASUS\\git\\firewall\\src\\rules.csv");
//            }, 0, 2, TimeUnit.MINUTES);
//    		
//    	
    

    	    // Simulate a DDoS attack from IP "192.168.1.100"
    	    for (int i = 0; i < 150; i++) {
    	        boolean allowed = firewall.accept_packet("inbound", "tcp", 80, "192.168.1.3");
    	        System.out.println("Request " + i  + ": " + allowed);
    	        if (!allowed) {
    	   
    	        break;
    	        }
    	    }

    	    // After removing the rule
    	    boolean allowed = firewall.accept_packet("inbound", "tcp", 80, "192.168.1.3");
    	    System.out.println("After removing the rule" + ": " + allowed);
    	   


    
    }
	
}
