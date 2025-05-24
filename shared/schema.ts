import { pgTable, text, serial, integer, boolean, timestamp, jsonb } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

// User authentication
export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
  role: text("role").notNull().default("user"),
  email: text("email"),
  lastLogin: timestamp("last_login"),
});

export const insertUserSchema = createInsertSchema(users).pick({
  username: true,
  password: true,
  role: true,
  email: true,
});

// Security events
export const securityEvents = pgTable("security_events", {
  id: serial("id").primaryKey(),
  timestamp: timestamp("timestamp").notNull().defaultNow(),
  eventType: text("event_type").notNull(),
  source: text("source").notNull(),
  destination: text("destination").notNull(),
  severity: text("severity").notNull(),
  status: text("status").notNull(),
  details: jsonb("details"),
});

export const insertSecurityEventSchema = createInsertSchema(securityEvents).pick({
  timestamp: true,
  eventType: true,
  source: true,
  destination: true,
  severity: true,
  status: true,
  details: true,
});

// Active threats
export const threats = pgTable("threats", {
  id: serial("id").primaryKey(),
  timestamp: timestamp("timestamp").notNull().defaultNow(),
  title: text("title").notNull(),
  description: text("description").notNull(),
  severity: text("severity").notNull(),
  status: text("status").notNull(),
  sourceIp: text("source_ip"),
  sourceCountry: text("source_country"),
  affectedSystems: jsonb("affected_systems"),
});

export const insertThreatSchema = createInsertSchema(threats).pick({
  timestamp: true,
  title: true,
  description: true,
  severity: true,
  status: true,
  sourceIp: true,
  sourceCountry: true,
  affectedSystems: true,
});

// System health metrics
export const systemHealth = pgTable("system_health", {
  id: serial("id").primaryKey(),
  timestamp: timestamp("timestamp").notNull().defaultNow(),
  systemName: text("system_name").notNull(),
  status: text("status").notNull(),
  healthPercentage: integer("health_percentage").notNull(),
  metrics: jsonb("metrics"),
});

export const insertSystemHealthSchema = createInsertSchema(systemHealth).pick({
  timestamp: true,
  systemName: true,
  status: true,
  healthPercentage: true,
  metrics: true,
});

// Firewall rules
export const firewallRules = pgTable("firewall_rules", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  description: text("description"),
  sourceIp: text("source_ip").notNull(),
  destinationIp: text("destination_ip").notNull(),
  port: integer("port"),
  protocol: text("protocol").notNull(),
  action: text("action").notNull(), // "allow" or "block"
  priority: integer("priority").notNull(),
  enabled: boolean("enabled").notNull().default(true),
});

export const insertFirewallRuleSchema = createInsertSchema(firewallRules).pick({
  name: true,
  description: true,
  sourceIp: true,
  destinationIp: true,
  port: true,
  protocol: true,
  action: true,
  priority: true,
  enabled: true,
});

// Vulnerability scans
export const vulnerabilities = pgTable("vulnerabilities", {
  id: serial("id").primaryKey(),
  scanDate: timestamp("scan_date").notNull().defaultNow(),
  hostIp: text("host_ip").notNull(),
  hostName: text("host_name"),
  vulnerabilityType: text("vulnerability_type").notNull(),
  severity: text("severity").notNull(),
  description: text("description").notNull(),
  remediation: text("remediation"),
  status: text("status").notNull(), // "open", "fixed", "in_progress"
});

export const insertVulnerabilitySchema = createInsertSchema(vulnerabilities).pick({
  scanDate: true,
  hostIp: true,
  hostName: true,
  vulnerabilityType: true,
  severity: true,
  description: true,
  remediation: true,
  status: true,
});

// Network traffic metrics
export const networkTraffic = pgTable("network_traffic", {
  id: serial("id").primaryKey(),
  timestamp: timestamp("timestamp").notNull().defaultNow(),
  inbound: integer("inbound").notNull(),
  outbound: integer("outbound").notNull(),
  blocked: integer("blocked").notNull(),
  interface: text("interface").notNull(),
});

export const insertNetworkTrafficSchema = createInsertSchema(networkTraffic).pick({
  timestamp: true,
  inbound: true,
  outbound: true,
  blocked: true,
  interface: true,
});

// Export types
export type InsertUser = z.infer<typeof insertUserSchema>;
export type User = typeof users.$inferSelect;

export type InsertSecurityEvent = z.infer<typeof insertSecurityEventSchema>;
export type SecurityEvent = typeof securityEvents.$inferSelect;

export type InsertThreat = z.infer<typeof insertThreatSchema>;
export type Threat = typeof threats.$inferSelect;

export type InsertSystemHealth = z.infer<typeof insertSystemHealthSchema>;
export type SystemHealth = typeof systemHealth.$inferSelect;

export type InsertFirewallRule = z.infer<typeof insertFirewallRuleSchema>;
export type FirewallRule = typeof firewallRules.$inferSelect;

export type InsertVulnerability = z.infer<typeof insertVulnerabilitySchema>;
export type Vulnerability = typeof vulnerabilities.$inferSelect;

export type InsertNetworkTraffic = z.infer<typeof insertNetworkTrafficSchema>;
export type NetworkTraffic = typeof networkTraffic.$inferSelect;
