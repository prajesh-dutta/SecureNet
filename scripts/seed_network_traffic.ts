import { db } from "../server/db";
import { networkTraffic } from "../shared/schema";

async function seedNetworkTraffic() {
  console.log("Seeding network traffic data...");
  
  // Generate 48 hours of network traffic data (one entry per hour)
  const now = new Date();
  const dataPoints = 48;
  
  for (let i = 0; i < dataPoints; i++) {
    // Create timestamp for each hour going backward from now
    const timestamp = new Date(now);
    timestamp.setHours(now.getHours() - (dataPoints - i));
    
    // Generate realistic traffic based on time of day
    const hour = timestamp.getHours();
    const isBusinessHours = hour >= 9 && hour <= 17;
    const isNighttime = hour >= 0 && hour <= 5;
    
    // Base traffic volume varies by time of day
    let baseTraffic;
    if (isBusinessHours) {
      baseTraffic = 500 + Math.floor(Math.random() * 300); // Higher during business hours
    } else if (isNighttime) {
      baseTraffic = 50 + Math.floor(Math.random() * 100); // Lower at night
    } else {
      baseTraffic = 200 + Math.floor(Math.random() * 200); // Medium otherwise
    }
    
    // Calculate traffic metrics with some randomness
    const inbound = baseTraffic + Math.floor(Math.random() * 100);
    const outbound = Math.floor(baseTraffic * 0.7 + Math.floor(Math.random() * 80)); // Outbound usually less than inbound
    const blocked = Math.floor(Math.random() * 50); // Small amount of malicious traffic
    
    try {
      // Insert network traffic data
      await db.insert(networkTraffic).values({
        inbound: inbound,
        outbound: outbound,
        blocked: blocked,
        interface: "eth0" // Main network interface
      });
      
      console.log(`Created network traffic record for ${timestamp.toISOString()} (In: ${inbound}, Out: ${outbound}, Blocked: ${blocked})`);
    } catch (error) {
      console.error("Error creating network traffic record:", error);
    }
  }
}

// Run the seeding process
seedNetworkTraffic()
  .then(() => {
    console.log("Network traffic seeding completed!");
    process.exit(0);
  })
  .catch((error) => {
    console.error("Error seeding network traffic:", error);
    process.exit(1);
  });