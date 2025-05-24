import { db } from "../server/db";
import {
  users,
  securityEvents,
  threats,
  systemHealth,
  firewallRules,
  vulnerabilities,
  networkTraffic
} from "../shared/schema";
import { eq } from "drizzle-orm";

// Helper function to generate random dates within a range
function randomDate(start: Date, end: Date): Date {
  return new Date(start.getTime() + Math.random() * (end.getTime() - start.getTime()));
}

// Helper function to generate random IP addresses
function randomIP(): string {
  return `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
}

// Helper function to generate random domain names
function randomDomain(): string {
  const prefixes = ["secure", "cyber", "threat", "malicious", "phish", "hack", "evil", "bad", "attack", "malware"];
  const suffixes = ["site", "domain", "server", "host", "net", "web", "cloud", "portal", "hub", "center"];
  const tlds = ["com", "org", "net", "io", "co", "info", "biz", "xyz"];
  
  const prefix = prefixes[Math.floor(Math.random() * prefixes.length)];
  const suffix = suffixes[Math.floor(Math.random() * suffixes.length)];
  const tld = tlds[Math.floor(Math.random() * tlds.length)];
  
  // Add some randomness
  if (Math.random() > 0.5) {
    const numbers = Math.floor(Math.random() * 9000) + 1000;
    return `${prefix}-${suffix}${numbers}.${tld}`;
  } else {
    return `${prefix}-${suffix}.${tld}`;
  }
}

// Seed admin user if it doesn't exist
async function seedUsers() {
  console.log("Seeding users...");

  // Check if admin user exists
  const existingAdmin = await db.select().from(users).where(eq(users.username, 'admin')).limit(1);
  
  if (existingAdmin.length === 0) {
    await db.insert(users).values({
      username: 'admin',
      password: '$2a$10$QJG9gQWvJPACEg1r0Pw.ReJ8VRQzzU0oZbX.k2FvZ.IPpbRTJfope', // hashed 'securenet'
      role: 'admin',
      email: 'admin@securenet.example',
      lastLogin: new Date()
    });
    console.log("Created admin user: admin / securenet");
  } else {
    console.log("Admin user already exists");
  }

  // Check if analyst user exists
  const existingAnalyst = await db.select().from(users).where(eq(users.username, 'analyst')).limit(1);
  
  if (existingAnalyst.length === 0) {
    await db.insert(users).values({
      username: 'analyst',
      password: '$2a$10$P6eAXGEGJ3xhzXkRGJ1J6uCnb8kl4UaERFFA6RYUn1QJVHmk8ThXu', // hashed 'analyst123'
      role: 'analyst',
      email: 'analyst@securenet.example',
      lastLogin: new Date()
    });
    console.log("Created analyst user: analyst / analyst123");
  } else {
    console.log("Analyst user already exists");
  }
}

// Seed security events
async function seedSecurityEvents(count = 50) {
  console.log(`Seeding ${count} security events...`);
  
  const eventTypes = [
    "Authentication Failure", 
    "Malware Detection", 
    "Firewall Block", 
    "Intrusion Attempt", 
    "Data Exfiltration", 
    "Privilege Escalation",
    "Suspicious Activity",
    "DDoS Attack",
    "Brute Force Attempt",
    "Abnormal Behavior"
  ];
  
  const severities = ["Critical", "Medium", "Low"];
  const statuses = ["Active", "Investigating", "Blocked"];
  
  const now = new Date();
  const sevenDaysAgo = new Date(now);
  sevenDaysAgo.setDate(now.getDate() - 7);
  
  for (let i = 0; i < count; i++) {
    const eventType = eventTypes[Math.floor(Math.random() * eventTypes.length)];
    const severity = severities[Math.floor(Math.random() * severities.length)];
    const status = statuses[Math.floor(Math.random() * statuses.length)];
    const source = randomIP();
    const destination = randomIP();
    const timestamp = randomDate(sevenDaysAgo, now).toISOString();
    
    await db.insert(securityEvents).values({
      timestamp,
      eventType,
      source,
      destination,
      severity,
      status
    });
  }
}

// Seed threats
async function seedThreats(count = 30) {
  console.log(`Seeding ${count} threats...`);
  
  const types = ["Malware", "Phishing", "Ransomware", "DDoS", "Zero-day", "Insider"];
  const severities = ["Critical", "High", "Medium", "Low"];
  const statuses = ["Active", "Mitigated", "Resolved"];
  
  const now = new Date();
  const thirtyDaysAgo = new Date(now);
  thirtyDaysAgo.setDate(now.getDate() - 30);
  
  for (let i = 0; i < count; i++) {
    const type = types[Math.floor(Math.random() * types.length)];
    const severity = severities[Math.floor(Math.random() * severities.length)];
    const status = statuses[Math.floor(Math.random() * statuses.length)];
    const detectedAt = randomDate(thirtyDaysAgo, now).toISOString();
    const source = randomIP();
    const targetSystem = Math.random() > 0.5 ? randomIP() : randomDomain();
    
    await db.insert(threats).values({
      type,
      severity,
      detectedAt,
      source,
      targetSystem,
      status,
      description: `${type} threat detected from ${source} targeting ${targetSystem}`,
      affectedSystems: Math.floor(Math.random() * 10) + 1
    });
  }
}

// Seed system health records
async function seedSystemHealth(count = 20) {
  console.log(`Seeding ${count} system health records...`);
  
  const statuses = ["Healthy", "Degraded", "Critical"];
  const systemTypes = ["Server", "Firewall", "Database", "Web Application", "Load Balancer", "IDS/IPS"];
  
  const now = new Date();
  const sevenDaysAgo = new Date(now);
  sevenDaysAgo.setDate(now.getDate() - 7);
  
  for (let i = 0; i < count; i++) {
    const status = statuses[Math.floor(Math.random() * statuses.length)];
    const systemType = systemTypes[Math.floor(Math.random() * systemTypes.length)];
    const cpuUsage = Math.floor(Math.random() * 100);
    const memoryUsage = Math.floor(Math.random() * 100);
    const diskUsage = Math.floor(Math.random() * 100);
    const timestamp = randomDate(sevenDaysAgo, now).toISOString();
    
    await db.insert(systemHealth).values({
      systemName: `${systemType}-${Math.floor(Math.random() * 100)}`,
      status,
      cpuUsage,
      memoryUsage,
      diskUsage,
      uptime: Math.floor(Math.random() * 30 * 24 * 60 * 60), // Random uptime in seconds up to 30 days
      timestamp
    });
  }
}

// Seed firewall rules
async function seedFirewallRules(count = 15) {
  console.log(`Seeding ${count} firewall rules...`);
  
  const actions = ["Allow", "Deny", "Log"];
  const protocols = ["TCP", "UDP", "ICMP", "Any"];
  const directions = ["Inbound", "Outbound"];
  
  for (let i = 0; i < count; i++) {
    const action = actions[Math.floor(Math.random() * actions.length)];
    const protocol = protocols[Math.floor(Math.random() * protocols.length)];
    const direction = directions[Math.floor(Math.random() * directions.length)];
    const sourceIP = Math.random() > 0.3 ? randomIP() : "Any";
    const destinationIP = Math.random() > 0.3 ? randomIP() : "Any";
    const sourcePort = Math.random() > 0.5 ? Math.floor(Math.random() * 65535) : "Any";
    const destinationPort = Math.random() > 0.5 ? Math.floor(Math.random() * 65535) : "Any";
    
    await db.insert(firewallRules).values({
      name: `Rule-${i+1}`,
      action,
      protocol,
      sourceIP,
      destinationIP,
      sourcePort: sourcePort.toString(),
      destinationPort: destinationPort.toString(),
      direction,
      enabled: Math.random() > 0.1, // 90% chance of being enabled
      priority: Math.floor(Math.random() * 100) + 1,
      description: `${action} ${protocol} traffic from ${sourceIP} to ${destinationIP}`
    });
  }
}

// Seed vulnerabilities
async function seedVulnerabilities(count = 25) {
  console.log(`Seeding ${count} vulnerabilities...`);
  
  const severities = ["Critical", "High", "Medium", "Low"];
  const statuses = ["Open", "In Progress", "Fixed", "False Positive"];
  const categories = ["Software", "Configuration", "Network", "Authentication", "Encryption"];
  
  const now = new Date();
  const ninetyDaysAgo = new Date(now);
  ninetyDaysAgo.setDate(now.getDate() - 90);
  
  for (let i = 0; i < count; i++) {
    const severity = severities[Math.floor(Math.random() * severities.length)];
    const status = statuses[Math.floor(Math.random() * statuses.length)];
    const category = categories[Math.floor(Math.random() * categories.length)];
    const discoveredAt = randomDate(ninetyDaysAgo, now).toISOString();
    
    // Generate CVE ID (some vulnerabilities might not have a CVE)
    let cveId = null;
    if (Math.random() > 0.2) { // 80% chance to have a CVE
      const year = Math.floor(Math.random() * 6) + 2018; // 2018-2023
      const number = Math.floor(Math.random() * 9000) + 1000;
      cveId = `CVE-${year}-${number}`;
    }
    
    // Generate title based on severity
    let title;
    if (severity === "Critical") {
      title = [
        "Remote Code Execution in Authentication Module",
        "SQL Injection in User Management Interface",
        "Privilege Escalation in Admin Console",
        "Buffer Overflow in Network Protocol Handler",
        "Authentication Bypass in Security Gateway"
      ][Math.floor(Math.random() * 5)];
    } else if (severity === "High") {
      title = [
        "Cross-Site Scripting in Web Dashboard",
        "Command Injection in Configuration Tool",
        "Information Disclosure in API Endpoint",
        "Insecure Deserialization in Message Processor",
        "Path Traversal in File Upload Component"
      ][Math.floor(Math.random() * 5)];
    } else if (severity === "Medium") {
      title = [
        "Cross-Site Request Forgery in User Settings",
        "Insecure Direct Object References in Profile Manager",
        "Weak Password Policy Implementation",
        "Insufficient Session Expiration Controls",
        "Missing HTTP Security Headers"
      ][Math.floor(Math.random() * 5)];
    } else {
      title = [
        "Clickjacking Vulnerability in Dashboard",
        "Information Exposure Through Error Messages",
        "Cache Management Issue",
        "Insecure Cookie Attributes",
        "HTTP Method Exposure"
      ][Math.floor(Math.random() * 5)];
    }
    
    // Calculate CVSS score based on severity
    let cvssScore;
    if (severity === "Critical") {
      cvssScore = (Math.random() * 1.0 + 9.0).toFixed(1);
    } else if (severity === "High") {
      cvssScore = (Math.random() * 1.9 + 7.0).toFixed(1);
    } else if (severity === "Medium") {
      cvssScore = (Math.random() * 2.9 + 4.0).toFixed(1);
    } else {
      cvssScore = (Math.random() * 3.9 + 0.1).toFixed(1);
    }
    
    await db.insert(vulnerabilities).values({
      title,
      description: `A ${severity.toLowerCase()} severity ${category.toLowerCase()} vulnerability that could allow attackers to compromise system security.`,
      cveId,
      severity,
      cvssScore: parseFloat(cvssScore),
      affectedSystem: Math.random() > 0.5 ? randomIP() : randomDomain(),
      status,
      category,
      discoveredAt,
      remediationSteps: `Apply the latest security patches and update all affected systems. Follow vendor recommendations.`
    });
  }
}

// Seed network traffic data
async function seedNetworkTraffic(count = 48) { // 48 hours of data
  console.log(`Seeding ${count} network traffic records...`);
  
  const now = new Date();
  
  for (let i = 0; i < count; i++) {
    const timestamp = new Date(now);
    timestamp.setHours(now.getHours() - (count - i));
    
    // Generate realistic traffic numbers that follow a pattern
    // More traffic during business hours (9am-5pm)
    const hour = timestamp.getHours();
    const isBusinessHours = hour >= 9 && hour <= 17;
    const isNighttime = hour >= 0 && hour <= 5;
    
    let baseTraffic;
    if (isBusinessHours) {
      baseTraffic = 500 + Math.floor(Math.random() * 300); // Higher during business hours
    } else if (isNighttime) {
      baseTraffic = 50 + Math.floor(Math.random() * 100); // Lower at night
    } else {
      baseTraffic = 200 + Math.floor(Math.random() * 200); // Medium otherwise
    }
    
    // Add some randomness for realistic fluctuations
    const inbound = baseTraffic + Math.floor(Math.random() * 100);
    const outbound = baseTraffic * 0.7 + Math.floor(Math.random() * 80); // Outbound usually less than inbound
    const maliciousTraffic = Math.floor(Math.random() * 50); // Small amount of malicious traffic
    
    await db.insert(networkTraffic).values({
      timestamp: timestamp.toISOString(),
      inboundTraffic: inbound,
      outboundTraffic: Math.floor(outbound),
      blockedTraffic: maliciousTraffic,
      totalConnections: Math.floor(inbound / 10) + Math.floor(outbound / 15), // Approx number of connections
      averageResponseTime: Math.floor(Math.random() * 200) + 50 // 50-250ms
    });
  }
}

// Main function to seed all data
async function seedDatabase() {
  try {
    console.log("Starting database seeding...");
    
    await seedUsers();
    await seedSecurityEvents();
    await seedThreats();
    await seedSystemHealth();
    await seedFirewallRules();
    await seedVulnerabilities();
    await seedNetworkTraffic();
    
    console.log("Database seeding completed successfully!");
    process.exit(0);
  } catch (error) {
    console.error("Error seeding database:", error);
    process.exit(1);
  }
}

// Run the seeding process
seedDatabase();