import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { 
  generateNetworkTrafficData, 
  generateSecurityEvents, 
  generateThreatLevelData,
  generateGeoThreatData,
  generateSystemStatusData,
  generateActiveAlerts,
  generateOverviewStats
} from "../client/src/lib/mock-data";

export async function registerRoutes(app: Express): Promise<Server> {
  // Security dashboard endpoints
  app.get("/api/dashboard/overview", (req, res) => {
    res.json(generateOverviewStats());
  });

  app.get("/api/dashboard/metrics", (req, res) => {
    res.json(generateSystemStatusData());
  });

  app.get("/api/threats", (req, res) => {
    res.json(generateSecurityEvents());
  });

  app.get("/api/threats/level", (req, res) => {
    res.json(generateThreatLevelData());
  });

  app.get("/api/threats/geo", (req, res) => {
    res.json(generateGeoThreatData());
  });

  app.get("/api/threats/alerts", (req, res) => {
    res.json(generateActiveAlerts());
  });

  app.get("/api/network/traffic", (req, res) => {
    res.json(generateNetworkTrafficData());
  });

  app.get("/api/network/topology", (req, res) => {
    res.json({ status: "success" });
  });

  // Authentication endpoint (for future implementation)
  app.post("/api/auth/login", (req, res) => {
    res.json({ 
      status: "success",
      token: "mock-jwt-token",
      user: {
        id: 1,
        username: "admin",
        role: "SOC Admin"
      }
    });
  });

  const httpServer = createServer(app);
  return httpServer;
}
