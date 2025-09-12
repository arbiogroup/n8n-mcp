import session from "express-session";
import { OAuthConfig } from "../config/oauth";

export function createSessionConfig(config: OAuthConfig) {
  return {
    secret: config.session.secret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
      sameSite: "lax" as const,
    },
    name: "n8n-mcp-session",
  };
}

export const sessionConfig = {
  secret: process.env.SESSION_SECRET || "fallback-secret-change-in-production",
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === "production",
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: "lax" as const,
  },
  name: "n8n-mcp-session",
};
