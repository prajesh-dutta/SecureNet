import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { setupAuth, isAuthenticated } from "./auth";
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
  // Set up authentication
  setupAuth(app);

  // Protected dashboard endpoints
  app.get("/api/dashboard/overview", isAuthenticated, (req, res) => {
    res.json(generateOverviewStats());
  });

  app.get("/api/dashboard/metrics", isAuthenticated, (req, res) => {
    res.json(generateSystemStatusData());
  });

  app.get("/api/threats", isAuthenticated, (req, res) => {
    res.json(generateSecurityEvents());
  });

  app.get("/api/threats/level", isAuthenticated, (req, res) => {
    res.json(generateThreatLevelData());
  });

  app.get("/api/threats/geo", isAuthenticated, (req, res) => {
    res.json(generateGeoThreatData());
  });

  app.get("/api/threats/alerts", isAuthenticated, (req, res) => {
    res.json(generateActiveAlerts());
  });

  app.get("/api/network/traffic", isAuthenticated, (req, res) => {
    res.json(generateNetworkTrafficData());
  });

  app.get("/api/network/topology", isAuthenticated, (req, res) => {
    res.json({ status: "success" });
  });

  const httpServer = createServer(app);
  return httpServer;
}
