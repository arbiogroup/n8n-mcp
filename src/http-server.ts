#!/usr/bin/env node
/**
 * Fixed HTTP server for n8n-MCP that properly handles StreamableHTTPServerTransport initialization
 * This implementation ensures the transport is properly initialized before handling requests
 */
import express from "express";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { n8nDocumentationToolsFinal } from "./mcp/tools";
import { n8nManagementTools } from "./mcp/tools-n8n-manager";
import { N8NDocumentationMCPServer } from "./mcp/server";
import { logger } from "./utils/logger";
import { PROJECT_VERSION } from "./utils/version";
import { isN8nApiConfigured } from "./config/n8n-api";
import dotenv from "dotenv";
import {
  getStartupBaseUrl,
  formatEndpointUrls,
  detectBaseUrl,
} from "./utils/url-detector";
import {
  negotiateProtocolVersion,
  logProtocolNegotiation,
  N8N_PROTOCOL_VERSION,
} from "./utils/protocol-version";
import { loadOAuthConfig } from "./config/oauth";
import { JWTService } from "./services/jwt-service";
import { OAuthMiddleware } from "./middleware/oauth";
import { OAuthHandlers } from "./routes/oauth";
import { createSessionConfig } from "./middleware/session";
import session from "express-session";
import passport from "passport";
import { createGoogleStrategy } from "./strategies/google-strategy";
import { OAuthErrorHandler } from "./middleware/error-handler";
import { MCPOAuthProxy } from "./mcp/oauth-proxy";
import { MCPConnectionWizard } from "./mcp/connection-wizard";
import { ZeroCopyOAuth } from "./mcp/zero-copy-oauth";

dotenv.config();

let expressServer: any;
let oauthConfig: any;
let jwtService: JWTService;
let oauthMiddleware: OAuthMiddleware;
let oauthHandlers: OAuthHandlers;
let mcpOAuthProxy: MCPOAuthProxy;
let connectionWizard: MCPConnectionWizard;
let zeroCopyOAuth: ZeroCopyOAuth;

/**
 * Initialize OAuth configuration and services
 */
function initializeOAuth() {
  try {
    oauthConfig = loadOAuthConfig();
    jwtService = new JWTService(oauthConfig);
    oauthMiddleware = new OAuthMiddleware(jwtService);
    oauthHandlers = new OAuthHandlers(jwtService, oauthConfig);
    mcpOAuthProxy = new MCPOAuthProxy(jwtService, oauthConfig);
    connectionWizard = new MCPConnectionWizard("http://localhost:3000"); // Will be updated with actual URL
    zeroCopyOAuth = new ZeroCopyOAuth(jwtService, oauthConfig);

    logger.info("OAuth system initialized successfully");
  } catch (error) {
    logger.error("Failed to initialize OAuth system", { error });
    console.error("ERROR: Failed to initialize OAuth system");
    console.error("Please check your OAuth environment variables");
    process.exit(1);
  }
}

/**
 * Graceful shutdown handler
 */
async function shutdown() {
  logger.info("Shutting down HTTP server...");
  console.log("Shutting down HTTP server...");

  if (expressServer) {
    expressServer.close(() => {
      logger.info("HTTP server closed");
      console.log("HTTP server closed");
      process.exit(0);
    });

    setTimeout(() => {
      logger.error("Forced shutdown after timeout");
      process.exit(1);
    }, 10000);
  } else {
    process.exit(0);
  }
}

export async function startFixedHTTPServer() {
  initializeOAuth();

  const app = express();

  // Configure trust proxy for correct IP logging behind reverse proxies
  const trustProxy = process.env.TRUST_PROXY
    ? Number(process.env.TRUST_PROXY)
    : 0;
  if (trustProxy > 0) {
    app.set("trust proxy", trustProxy);
    logger.info(`Trust proxy enabled with ${trustProxy} hop(s)`);
  }

  // CRITICAL: Don't use any body parser - StreamableHTTPServerTransport needs raw stream

  // Security headers
  app.use((req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("X-XSS-Protection", "1; mode=block");
    res.setHeader(
      "Strict-Transport-Security",
      "max-age=31536000; includeSubDomains"
    );
    next();
  });

  // CORS configuration
  app.use((req, res, next) => {
    const allowedOrigin = process.env.CORS_ORIGIN || "*";
    res.setHeader("Access-Control-Allow-Origin", allowedOrigin);
    res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
    res.setHeader(
      "Access-Control-Allow-Headers",
      "Content-Type, Authorization, Accept"
    );
    res.setHeader("Access-Control-Max-Age", "86400");

    if (req.method === "OPTIONS") {
      res.sendStatus(204);
      return;
    }
    next();
  });

  // Session configuration for OAuth
  app.use(session(createSessionConfig(oauthConfig)));

  // Initialize Passport
  app.use(passport.initialize());
  app.use(passport.session());

  // Configure Google OAuth strategy
  const googleStrategy = createGoogleStrategy(oauthConfig);
  passport.use(googleStrategy);

  // Serialize/deserialize user for session
  passport.serializeUser((user: any, done: (err: any, user?: any) => void) => {
    done(null, user);
  });

  passport.deserializeUser(
    (user: any, done: (err: any, user?: any) => void) => {
      done(null, user);
    }
  );

  // Request logging
  app.use((req, res, next) => {
    logger.info(`${req.method} ${req.path}`, {
      ip: req.ip,
      userAgent: req.get("user-agent"),
      contentLength: req.get("content-length"),
    });
    next();
  });

  // Create a single persistent MCP server instance
  const mcpServer = new N8NDocumentationMCPServer();
  logger.info("Created persistent MCP server instance");

  // Simple landing page for zero-copy OAuth
  app.get("/", (req, res) => {
    res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>n8n MCP Server - Zero Copy OAuth</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            background: white;
            border-radius: 12px;
            padding: 40px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            text-align: center;
        }
        .title {
            color: #2d3748;
            font-size: 32px;
            margin-bottom: 10px;
        }
        .subtitle {
            color: #718096;
            font-size: 18px;
            margin-bottom: 30px;
        }
        .description {
            color: #4a5568;
            font-size: 16px;
            line-height: 1.6;
            margin-bottom: 40px;
        }
        .btn {
            background: #667eea;
            color: white;
            border: none;
            padding: 15px 30px;
            border-radius: 8px;
            font-size: 18px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
            transition: all 0.2s;
            margin: 10px;
        }
        .btn:hover {
            background: #5a67d8;
            transform: translateY(-2px);
        }
        .features {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 40px 0;
        }
        .feature {
            padding: 20px;
            background: #f7fafc;
            border-radius: 8px;
            text-align: center;
        }
        .feature-icon {
            font-size: 32px;
            margin-bottom: 10px;
        }
        .feature-title {
            font-weight: 600;
            color: #2d3748;
            margin-bottom: 5px;
        }
        .feature-desc {
            color: #718096;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1 class="title">🚀 n8n MCP Server</h1>
        <p class="subtitle">Zero Copy-Paste OAuth Authentication</p>
        
        <p class="description">
            Connect your MCP client to n8n documentation and workflow management tools 
            with just one click. No manual configuration, no copy-pasting tokens - 
            just authenticate and you're connected!
        </p>

        <div class="features">
            <div class="feature">
                <div class="feature-icon">🔐</div>
                <div class="feature-title">One-Click Auth</div>
                <div class="feature-desc">Login with Google once</div>
            </div>
            <div class="feature">
                <div class="feature-icon">🤖</div>
                <div class="feature-title">Auto-Configure</div>
                <div class="feature-desc">Automatically detects your MCP client</div>
            </div>
            <div class="feature">
                <div class="feature-icon">⚡</div>
                <div class="feature-title">Zero Setup</div>
                <div class="feature-desc">No manual configuration needed</div>
            </div>
        </div>

        <a href="/connect" class="btn">Connect Your MCP Client</a>
        <a href="/health" class="btn" style="background: #e2e8f0; color: #4a5568;">View API Status</a>
    </div>
</body>
</html>`);
  });

  // Root endpoint with API information (for developers)
  app.get("/api", (req, res) => {
    const port = parseInt(process.env.PORT || "3000");
    const host = process.env.HOST || "0.0.0.0";
    const baseUrl = detectBaseUrl(req, host, port);
    const endpoints = formatEndpointUrls(baseUrl);

    res.json({
      name: "n8n Documentation MCP Server",
      version: PROJECT_VERSION,
      description:
        "Model Context Protocol server providing comprehensive n8n node documentation and workflow management",
      endpoints: {
        health: {
          url: endpoints.health,
          method: "GET",
          description: "Health check and status information",
        },
        mcp: {
          url: endpoints.mcp,
          method: "GET/POST",
          description: "MCP endpoint - GET for info, POST for JSON-RPC",
        },
      },
      authentication: {
        type: "OAuth 2.0 with JWT",
        header: "Authorization: Bearer <jwt_token>",
        required_for: ["POST /mcp"],
        oauth_endpoints: {
          google: "/auth/google",
          callback: "/auth/google/callback",
          verify: "/auth/verify",
          refresh: "/auth/refresh",
          logout: "/auth/logout",
        },
        mcp_oauth_proxy: {
          register: "/oauth/register",
          authorize: "/oauth/authorize", 
          token: "/oauth/token",
          discover: "/oauth/discover",
        },
        zero_copy_oauth: "/connect",
      },
      documentation: "https://github.com/czlonkowski/n8n-mcp",
    });
  });

  // Health check endpoint
  app.get("/health", (req, res) => {
    res.json({
      status: "ok",
      mode: "http-fixed",
      version: PROJECT_VERSION,
      uptime: Math.floor(process.uptime()),
      memory: {
        used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
        total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024),
        unit: "MB",
      },
      authentication: {
        type: "OAuth 2.0 with JWT",
        enabled: true,
        providers: ["google"],
        endpoints: {
          config: "/auth/config",
          google: "/auth/google",
          verify: "/auth/verify",
          refresh: "/auth/refresh",
          logout: "/auth/logout",
        },
      },
      timestamp: new Date().toISOString(),
    });
  });

  // Version endpoint
  app.get("/version", (req, res) => {
    res.json({
      version: PROJECT_VERSION,
      buildTime: new Date().toISOString(),
      tools: n8nDocumentationToolsFinal.map((t) => t.name),
      commit: process.env.GIT_COMMIT || "unknown",
    });
  });

  // Test tools endpoint
  app.get("/test-tools", async (req, res) => {
    try {
      const result = await mcpServer.executeTool("get_node_essentials", {
        nodeType: "nodes-base.httpRequest",
      });
      res.json({
        status: "ok",
        hasData: !!result,
        toolCount: n8nDocumentationToolsFinal.length,
      });
    } catch (error) {
      res.json({
        status: "error",
        message: error instanceof Error ? error.message : "Unknown error",
      });
    }
  });

  // Zero Copy-Paste OAuth routes
  app.get("/connect", zeroCopyOAuth.startOAuth);
  app.get("/authorize", zeroCopyOAuth.startOAuth);
  
  app.get(
    "/auth/google",
    passport.authenticate("google", { scope: ["openid", "email", "profile"] })
  );

  app.get(
    "/auth/google/callback",
    passport.authenticate("google", { failureRedirect: "/auth/error" }),
    zeroCopyOAuth.handleCallback
  );

  app.get("/auth/verify", oauthHandlers.verifyToken);
  app.post("/auth/refresh", oauthHandlers.refreshToken);
  app.post("/auth/logout", oauthHandlers.logout);
  app.get("/auth/config", oauthHandlers.getConfig);

  // MCP OAuth Proxy routes (RFC 7591 Dynamic Client Registration)
  app.post("/oauth/register", mcpOAuthProxy.registerClient);
  app.get("/oauth/authorize", mcpOAuthProxy.authorize);
  app.post("/oauth/token", mcpOAuthProxy.token);
  app.get("/oauth/discover", mcpOAuthProxy.discover);

  // MCP Connection Wizard routes
  app.get("/mcp/connect", connectionWizard.renderWizard);
  app.post("/mcp/connect/select", connectionWizard.selectClient);
  app.get("/mcp/connect/claude-desktop", connectionWizard.claudeDesktopFlow);
  app.get("/mcp/connect/windsurf", connectionWizard.windsurfFlow);
  app.get("/mcp/connect/custom", connectionWizard.customClientFlow);
  app.get("/mcp/discover", mcpOAuthProxy.discover);
  
  // OAuth error page
  app.get("/auth/error", (req, res) => {
    res.status(401).json({
      success: false,
      error: {
        code: "AUTHENTICATION_FAILED",
        message: "OAuth authentication failed. Please try again.",
      },
      timestamp: new Date().toISOString(),
    });
  });


  // OAuth error handling middleware
  app.use("/auth", OAuthErrorHandler.handleNotFound);

  // MCP information endpoint (no auth required for discovery)
  app.get("/mcp", (req, res) => {
    res.json({
      description: "n8n Documentation MCP Server",
      version: PROJECT_VERSION,
      endpoints: {
        mcp: {
          method: "POST",
          path: "/mcp",
          description: "Main MCP JSON-RPC endpoint",
          authentication: "Bearer token required",
        },
        health: {
          method: "GET",
          path: "/health",
          description: "Health check endpoint",
          authentication: "None",
        },
        root: {
          method: "GET",
          path: "/",
          description: "API information",
          authentication: "None",
        },
      },
      documentation: "https://github.com/czlonkowski/n8n-mcp",
    });
  });

  // Main MCP endpoint - handle each request with OAuth authentication
  app.post(
    "/mcp",
    oauthMiddleware.authenticateToken,
    async (req: express.Request, res: express.Response): Promise<void> => {
      const startTime = Date.now();

      try {
        // Instead of using StreamableHTTPServerTransport, we'll handle the request directly
        // This avoids the initialization issues with the transport

        // Collect the raw body
        let body = "";
        req.on("data", (chunk) => {
          body += chunk.toString();
        });

        req.on("end", async () => {
          try {
            const jsonRpcRequest = JSON.parse(body);
            logger.debug("Received JSON-RPC request:", {
              method: jsonRpcRequest.method,
            });

            // Handle the request based on method
            let response;

            switch (jsonRpcRequest.method) {
              case "initialize":
                // Negotiate protocol version for this client/request
                const negotiationResult = negotiateProtocolVersion(
                  jsonRpcRequest.params?.protocolVersion,
                  jsonRpcRequest.params?.clientInfo,
                  req.get("user-agent"),
                  req.headers
                );

                logProtocolNegotiation(
                  negotiationResult,
                  logger,
                  "HTTP_SERVER_INITIALIZE"
                );

                response = {
                  jsonrpc: "2.0",
                  result: {
                    protocolVersion: negotiationResult.version,
                    capabilities: {
                      tools: {},
                      resources: {},
                    },
                    serverInfo: {
                      name: "n8n-documentation-mcp",
                      version: PROJECT_VERSION,
                    },
                  },
                  id: jsonRpcRequest.id,
                };
                break;

              case "tools/list":
                // Use the proper tool list that includes management tools when configured
                const tools = [...n8nDocumentationToolsFinal];

                // Add management tools if n8n API is configured
                if (isN8nApiConfigured()) {
                  tools.push(...n8nManagementTools);
                }

                response = {
                  jsonrpc: "2.0",
                  result: {
                    tools,
                  },
                  id: jsonRpcRequest.id,
                };
                break;

              case "tools/call":
                // Delegate to the MCP server
                const toolName = jsonRpcRequest.params?.name;
                const toolArgs = jsonRpcRequest.params?.arguments || {};

                try {
                  const result = await mcpServer.executeTool(
                    toolName,
                    toolArgs
                  );
                  response = {
                    jsonrpc: "2.0",
                    result: {
                      content: [
                        {
                          type: "text",
                          text: JSON.stringify(result, null, 2),
                        },
                      ],
                    },
                    id: jsonRpcRequest.id,
                  };
                } catch (error) {
                  response = {
                    jsonrpc: "2.0",
                    error: {
                      code: -32603,
                      message: `Error executing tool ${toolName}: ${
                        error instanceof Error ? error.message : "Unknown error"
                      }`,
                    },
                    id: jsonRpcRequest.id,
                  };
                }
                break;

              default:
                response = {
                  jsonrpc: "2.0",
                  error: {
                    code: -32601,
                    message: `Method not found: ${jsonRpcRequest.method}`,
                  },
                  id: jsonRpcRequest.id,
                };
            }

            // Send response
            res.setHeader("Content-Type", "application/json");
            res.json(response);

            const duration = Date.now() - startTime;
            logger.info("MCP request completed", {
              duration,
              method: jsonRpcRequest.method,
            });
          } catch (error) {
            logger.error("Error processing request:", error);
            res.status(400).json({
              jsonrpc: "2.0",
              error: {
                code: -32700,
                message: "Parse error",
                data: error instanceof Error ? error.message : "Unknown error",
              },
              id: null,
            });
          }
        });
      } catch (error) {
        logger.error("MCP request error:", error);

        if (!res.headersSent) {
          res.status(500).json({
            jsonrpc: "2.0",
            error: {
              code: -32603,
              message: "Internal server error",
              data:
                process.env.NODE_ENV === "development"
                  ? (error as Error).message
                  : undefined,
            },
            id: null,
          });
        }
      }
    }
  );

  // 404 handler
  app.use((req, res) => {
    res.status(404).json({
      error: "Not found",
      message: `Cannot ${req.method} ${req.path}`,
    });
  });

  // Error handler
  app.use(
    (
      err: any,
      req: express.Request,
      res: express.Response,
      next: express.NextFunction
    ) => {
      logger.error("Express error handler:", err);

      if (!res.headersSent) {
        // Handle OAuth errors differently
        if (req.path.startsWith("/auth/")) {
          OAuthErrorHandler.handleOAuthError(err, req, res, next);
        } else {
          // Handle MCP errors with JSON-RPC format
          res.status(500).json({
            jsonrpc: "2.0",
            error: {
              code: -32603,
              message: "Internal server error",
              data:
                process.env.NODE_ENV === "development"
                  ? err.message
                  : undefined,
            },
            id: null,
          });
        }
      }
    }
  );

  const port = parseInt(process.env.PORT || "3000");
  const host = process.env.HOST || "0.0.0.0";

  expressServer = app.listen(port, host, () => {
    logger.info(`n8n MCP Fixed HTTP Server started`, { port, host });

    // Detect the base URL using our utility
    const baseUrl = getStartupBaseUrl(host, port);
    const endpoints = formatEndpointUrls(baseUrl);

    console.log(`n8n MCP Fixed HTTP Server running on ${host}:${port}`);
    console.log(`Health check: ${endpoints.health}`);
    console.log(`MCP endpoint: ${endpoints.mcp}`);
    console.log("\nPress Ctrl+C to stop the server");

    if (process.env.BASE_URL || process.env.PUBLIC_URL) {
      console.log(`\nPublic URL configured: ${baseUrl}`);
    } else if (process.env.TRUST_PROXY && Number(process.env.TRUST_PROXY) > 0) {
      console.log(
        `\nNote: TRUST_PROXY is enabled. URLs will be auto-detected from proxy headers.`
      );
    }
  });

  // Handle errors
  expressServer.on("error", (error: any) => {
    if (error.code === "EADDRINUSE") {
      logger.error(`Port ${port} is already in use`);
      console.error(`ERROR: Port ${port} is already in use`);
      process.exit(1);
    } else {
      logger.error("Server error:", error);
      console.error("Server error:", error);
      process.exit(1);
    }
  });

  // Graceful shutdown handlers
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);

  // Handle uncaught errors
  process.on("uncaughtException", (error) => {
    logger.error("Uncaught exception:", error);
    console.error("Uncaught exception:", error);
    shutdown();
  });

  process.on("unhandledRejection", (reason, promise) => {
    logger.error("Unhandled rejection:", reason);
    console.error("Unhandled rejection at:", promise, "reason:", reason);
    shutdown();
  });
}

// Make executeTool public on the server
declare module "./mcp/server" {
  interface N8NDocumentationMCPServer {
    executeTool(name: string, args: any): Promise<any>;
  }
}

// Start if called directly
// Check if this file is being run directly (not imported)
// In ES modules, we check import.meta.url against process.argv[1]
// But since we're transpiling to CommonJS, we use the require.main check
if (typeof require !== "undefined" && require.main === module) {
  startFixedHTTPServer().catch((error) => {
    logger.error("Failed to start Fixed HTTP server:", error);
    console.error("Failed to start Fixed HTTP server:", error);
    process.exit(1);
  });
}
