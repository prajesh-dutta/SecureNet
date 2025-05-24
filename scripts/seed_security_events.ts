import { db } from "../server/db";
import { securityEvents } from "../shared/schema";

async function seedSecurityEvents() {
  console.log("Seeding security events...");
  
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
  
  // Generate 50 security events
  for (let i = 0; i < 50; i++) {
    // Generate random IP addresses
    const source = `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
    const destination = `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
    
    // Select random values from our arrays
    const eventType = eventTypes[Math.floor(Math.random() * eventTypes.length)];
    const severity = severities[Math.floor(Math.random() * severities.length)];
    const status = statuses[Math.floor(Math.random() * statuses.length)];
    
    // Create the security event
    try {
      await db.insert(securityEvents).values({
        eventType,
        source,
        destination,
        severity,
        status
      });
      console.log(`Created security event: ${eventType} from ${source}`);
    } catch (error) {
      console.error("Error creating security event:", error);
    }
  }
}

// Run the seeding process
seedSecurityEvents()
  .then(() => {
    console.log("Security events seeding completed!");
    process.exit(0);
  })
  .catch((error) => {
    console.error("Error seeding security events:", error);
    process.exit(1);
  });