#!/usr/bin/env node
/**
 * Fixed HTTP server for n8n-MCP that properly handles StreamableHTTPServerTransport initialization
 * This implementation ensures the transport is properly initialized before handling requests
 */
import express from 'express';
import session from 'express-session';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { n8nDocumentationToolsFinal } from './mcp/tools';
import { n8nManagementTools } from './mcp/tools-n8n-manager';
import { N8NDocumentationMCPServer } from './mcp/server';
import { logger } from './utils/logger';
import { PROJECT_VERSION } from './utils/version';
import { isN8nApiConfigured } from './config/n8n-api';
import { getOAuthConfig } from './config/oauth';
import dotenv from 'dotenv';
import { readFileSync } from 'fs';
import { getStartupBaseUrl, formatEndpointUrls, detectBaseUrl } from './utils/url-detector';
import { 
  negotiateProtocolVersion, 
  logProtocolNegotiation,
  N8N_PROTOCOL_VERSION 
} from './utils/protocol-version';

// OAuth imports
import { createDatabaseAdapter } from './database/database-adapter';
import { OAuthRepository } from './repositories/oauth-repository';
import { OAuthService } from './services/oauth-service';
import { GoogleOAuthService } from './services/google-oauth-service';
import { createOAuthMiddleware, createOptionalOAuthMiddleware } from './middleware/oauth-middleware';

// Route imports
import { createAuthorizeRouter } from './routes/oauth-authorize';
import { createTokenRouter } from './routes/oauth-token';
import { createDiscoveryRouter } from './routes/oauth-discovery';
import { createClientManagementRouter } from './routes/oauth-clients';
import { createGoogleOAuthRouter } from './routes/google-oauth';

dotenv.config();

let expressServer: any;

// OAuth services
let oauthService: OAuthService | null = null;
let googleOAuthService: GoogleOAuthService | null = null;
let oauthMiddleware: any;
let optionalOAuthMiddleware: any;

/**
 * Load auth token from environment variable or file
 */
export function loadAuthToken(): string | null {
  // First, try AUTH_TOKEN environment variable
  if (process.env.AUTH_TOKEN) {
    logger.info('Using AUTH_TOKEN from environment variable');
    return process.env.AUTH_TOKEN;
  }
  
  // Then, try AUTH_TOKEN_FILE
  if (process.env.AUTH_TOKEN_FILE) {
    try {
      const token = readFileSync(process.env.AUTH_TOKEN_FILE, 'utf-8').trim();
      logger.info(`Loaded AUTH_TOKEN from file: ${process.env.AUTH_TOKEN_FILE}`);
      return token;
    } catch (error) {
      logger.error(`Failed to read AUTH_TOKEN_FILE: ${process.env.AUTH_TOKEN_FILE}`, error);
      console.error(`ERROR: Failed to read AUTH_TOKEN_FILE: ${process.env.AUTH_TOKEN_FILE}`);
      console.error(error instanceof Error ? error.message : 'Unknown error');
      return null;
    }
  }
  
  return null;
}

/**
 * Graceful shutdown handler
 */
async function shutdown() {
  logger.info('Shutting down HTTP server...');
  console.log('Shutting down HTTP server...');
  
  if (expressServer) {
    expressServer.close(() => {
      logger.info('HTTP server closed');
      console.log('HTTP server closed');
      process.exit(0);
    });
    
    setTimeout(() => {
      logger.error('Forced shutdown after timeout');
      process.exit(1);
    }, 10000);
  } else {
    process.exit(0);
  }
}


export async function startFixedHTTPServer() {
  
  const app = express();
  
  // Initialize OAuth services
  try {
    logger.info('Attempting to initialize OAuth services...');
    const oauthConfig = getOAuthConfig();
    logger.info('OAuth config loaded:', {
      issuer: oauthConfig.OAUTH_ISSUER,
      googleClientId: !!oauthConfig.GOOGLE_CLIENT_ID,
      googleClientSecret: !!oauthConfig.GOOGLE_CLIENT_SECRET,
      jwtSecret: !!oauthConfig.JWT_SECRET,
      domainRestriction: oauthConfig.OAUTH_DOMAIN_RESTRICTION
    });
    
    const dbAdapter = await createDatabaseAdapter('./data/nodes.db');
    logger.info('Database adapter created successfully');
    
    const oauthRepository = new OAuthRepository(dbAdapter);
    logger.info('OAuth repository created successfully');
    
    oauthService = new OAuthService(oauthRepository);
    googleOAuthService = new GoogleOAuthService();
    logger.info('OAuth services created successfully');
    
    // Initialize OAuth middleware
    oauthMiddleware = createOAuthMiddleware(oauthService);
    optionalOAuthMiddleware = createOptionalOAuthMiddleware(oauthService);
    logger.info('OAuth middleware created successfully');
    
    logger.info('✅ OAuth 2.1 services initialized successfully with dynamic client registration enabled');
  } catch (error) {
    logger.error('❌ Failed to initialize OAuth services:', error);
    console.error('OAuth initialization failed:', error);
    // Continue without OAuth if initialization fails
    oauthService = null;
    googleOAuthService = null;
  }
  
  // Configure trust proxy for correct IP logging behind reverse proxies
  const trustProxy = process.env.TRUST_PROXY ? Number(process.env.TRUST_PROXY) : 0;
  if (trustProxy > 0) {
    app.set('trust proxy', trustProxy);
    logger.info(`Trust proxy enabled with ${trustProxy} hop(s)`);
  }
  
  // Session configuration for OAuth
  if (oauthService) {
    const oauthConfig = getOAuthConfig();
    app.use(session({
      secret: oauthConfig.JWT_SECRET || 'fallback-session-secret',
      resave: false,
      saveUninitialized: false,
      cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
      },
      name: 'n8n-mcp-session'
    }));
    
    logger.info('Session middleware configured for OAuth');
  }
  
  // CRITICAL: Don't use JSON body parser globally - StreamableHTTPServerTransport needs raw stream
  // Global JSON parsing for all routes (needed for OAuth registration)
  app.use(express.json({ limit: '10mb' }));
  
  // OAuth endpoints also need URL-encoded parsing
  app.use('/authorize', express.urlencoded({ extended: true }));
  app.use('/oauth', express.urlencoded({ extended: true }));
  app.use('/register', express.urlencoded({ extended: true }));
  
  // OAuth token endpoints need both JSON and URL-encoded parsing
  app.use('/token', express.urlencoded({ extended: true }));
  app.use('/revoke', express.urlencoded({ extended: true }));
  app.use('/introspect', express.urlencoded({ extended: true }));
  
  // Security headers
  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    next();
  });
  
  // CORS configuration
  app.use((req, res, next) => {
    const allowedOrigin = process.env.CORS_ORIGIN || '*';
    res.setHeader('Access-Control-Allow-Origin', allowedOrigin);
    res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, Accept');
    res.setHeader('Access-Control-Max-Age', '86400');
    
    if (req.method === 'OPTIONS') {
      res.sendStatus(204);
      return;
    }
    next();
  });
  
  // Request logging
  app.use((req, res, next) => {
    logger.info(`${req.method} ${req.path}`, {
      ip: req.ip,
      userAgent: req.get('user-agent'),
      contentLength: req.get('content-length'),
      contentType: req.get('content-type')
    });
    next();
  });

  // Debug middleware for OAuth endpoints
  app.use(['/token', '/revoke', '/introspect', '/authorize'], (req, res, next) => {
    logger.info(`OAuth endpoint hit: ${req.method} ${req.path}`, {
      query: req.query,
      hasBody: !!req.body,
      bodyKeys: req.body ? Object.keys(req.body) : [],
      contentType: req.get('content-type')
    });
    next();
  });
  
  // Create a single persistent MCP server instance
  const mcpServer = new N8NDocumentationMCPServer();
  logger.info('Created persistent MCP server instance');
  
  // Mount OAuth routes if services are available
  if (oauthService && googleOAuthService) {
    logger.info('🔧 Mounting OAuth routes...');
    
    // OAuth Discovery and OpenID Connect endpoints
    app.use('/', createDiscoveryRouter());
    logger.info('✅ Discovery routes mounted');
    
    // Google OAuth routes
    app.use('/', createGoogleOAuthRouter(googleOAuthService));
    logger.info('✅ Google OAuth routes mounted');
    
    // OAuth Authorization and Token endpoints (without /oauth prefix)
    app.use('/', createAuthorizeRouter(oauthService, googleOAuthService));
    logger.info('✅ Authorization routes mounted at /authorize');
    
    app.use('/', createTokenRouter(oauthService));
    logger.info('✅ Token routes mounted at /token');
    
    // Mount client registration at root level for MCP compliance
    const clientRouter = createClientManagementRouter(oauthService);
    app.use('/', clientRouter);
    logger.info('✅ Client registration routes mounted at /register (MCP compliant)');
    
    // Keep admin endpoints at /oauth prefix for backward compatibility  
    app.use('/oauth', createClientManagementRouter(oauthService));
    logger.info('✅ Client management routes also mounted at /oauth (legacy)');
    
    logger.info('🎉 All OAuth 2.1 routes mounted successfully');
  } else {
    logger.warn('⚠️ OAuth services not available - routes not mounted');
    logger.warn('⚠️ OAuth service exists:', !!oauthService);
    logger.warn('⚠️ Google OAuth service exists:', !!googleOAuthService);
  }

  // Root endpoint with API information
  app.get('/', (req, res) => {
    const port = parseInt(process.env.PORT || '3000');
    const host = process.env.HOST || '0.0.0.0';
    
    // Use OAuth issuer URL if available, otherwise detect from request
    const oauthConfig = getOAuthConfig();
    const baseUrl = oauthConfig.OAUTH_ISSUER || detectBaseUrl(req, host, port);
    const endpoints = formatEndpointUrls(baseUrl);
    
    const responseData: any = {
      name: 'n8n Documentation MCP Server with OAuth 2.1 - Free Scope',
      version: PROJECT_VERSION,
      description: 'Model Context Protocol server with OAuth 2.1 authentication - Free scope policy allowing any client to register with any scopes',
      endpoints: {
        health: {
          url: endpoints.health,
          method: 'GET',
          description: 'Health check and status information'
        },
        mcp: {
          url: endpoints.mcp,
          method: 'GET/POST',
          description: 'MCP endpoint - GET for info, POST for JSON-RPC'
        }
      },
      authentication: {
        legacy: {
          type: 'Bearer Token',
          header: 'Authorization: Bearer <token>',
          required_for: ['POST /mcp (fallback)']
        }
      },
      documentation: 'https://github.com/czlonkowski/n8n-mcp'
    };
    
    // Add OAuth endpoints if available
    if (oauthService) {
      responseData.endpoints.oauth = {
        authorize: `${baseUrl}/authorize`,
        token: `${baseUrl}/token`,
        revoke: `${baseUrl}/revoke`,
        introspect: `${baseUrl}/introspect`,
        register: `${baseUrl}/register`,
        discovery: `${baseUrl}/.well-known/oauth-authorization-server`
      };
      
      responseData.oauth_policy = {
        scope_validation: 'disabled',
        client_registration: 'completely open',
        supported_scopes: '*',
        dynamic_registration: true,
        description: 'This server accepts ANY scopes from ANY client - completely free OAuth policy'
      };
      
      responseData.mcp_compliance = {
        specification_version: '2025-03-26',
        oauth_2_1: true,
        pkce_required: true,
        dynamic_registration: true,
        metadata_discovery: true,
        third_party_auth: true,
        compliant_endpoints: {
          authorization: '/authorize',
          token: '/token', 
          registration: '/register',
          metadata: '/.well-known/oauth-authorization-server'
        }
      };
      
      responseData.endpoints.auth = {
        google: `${baseUrl}/auth/google`,
        callback: `${baseUrl}/auth/google/callback`,
        user: `${baseUrl}/auth/user`,
        logout: `${baseUrl}/auth/logout`
      };
      
      responseData.endpoints.openid = {
        userinfo: `${baseUrl}/oauth/userinfo`
      };
      
      responseData.authentication.oauth2 = {
        type: 'OAuth 2.1',
        authorization_endpoint: `${baseUrl}/authorize`,
        token_endpoint: `${baseUrl}/token`,
        scopes: 'Any scopes accepted'
      };
    }
    
    res.json(responseData);
  });

  // Health check endpoint
  app.get('/health', (req, res) => {
    res.json({ 
      status: 'ok', 
      mode: 'http-fixed',
      version: PROJECT_VERSION,
      uptime: Math.floor(process.uptime()),
      memory: {
        used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
        total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024),
        unit: 'MB'
      },
      timestamp: new Date().toISOString()
    });
  });

  // Version endpoint
  app.get('/version', (req, res) => {
    res.json({ 
      version: PROJECT_VERSION,
      buildTime: new Date().toISOString(),
      tools: n8nDocumentationToolsFinal.map(t => t.name),
      commit: process.env.GIT_COMMIT || 'unknown'
    });
  });

  // Test tools endpoint
  app.get('/test-tools', async (req, res) => {
    try {
      const result = await mcpServer.executeTool('get_node_essentials', { nodeType: 'nodes-base.httpRequest' });
      res.json({ status: 'ok', hasData: !!result, toolCount: n8nDocumentationToolsFinal.length });
    } catch (error) {
      res.json({ status: 'error', message: error instanceof Error ? error.message : 'Unknown error' });
    }
  });
  
  // MCP information endpoint (no auth required for discovery)
  app.get('/mcp', (req, res) => {
    res.json({
      description: 'n8n Documentation MCP Server',
      version: PROJECT_VERSION,
      endpoints: {
        mcp: {
          method: 'POST',
          path: '/mcp',
          description: 'Main MCP JSON-RPC endpoint',
          authentication: 'Bearer token required'
        },
        health: {
          method: 'GET',
          path: '/health',
          description: 'Health check endpoint',
          authentication: 'None'
        },
        root: {
          method: 'GET',
          path: '/',
          description: 'API information',
          authentication: 'None'
        }
      },
      documentation: 'https://github.com/czlonkowski/n8n-mcp'
    });
  });

  // Main MCP endpoint - handle each request with custom transport handling
  // Now supports both OAuth and legacy Bearer token authentication
  app.post('/mcp', optionalOAuthMiddleware || ((req: any, res: any, next: any) => next()), async (req: express.Request, res: express.Response): Promise<void> => {
    const startTime = Date.now();
    
    // Check if user is authenticated via OAuth
    const isOAuthAuthenticated = (req as any).user && (req as any).user.isValid;
    let authenticationMethod = 'none';
    
    if (isOAuthAuthenticated) {
      authenticationMethod = 'oauth';
      logger.debug('MCP request authenticated via OAuth', {
        user: (req as any).user.email,
        clientId: (req as any).user.clientId
      });
    } else {
      res.status(401).json({
        jsonrpc: '2.0',
        error: {
          code: -32001,
          message: 'Unauthorized'
        },
        id: null
      });
      return;
    }
    
    try {
      // Instead of using StreamableHTTPServerTransport, we'll handle the request directly
      // This avoids the initialization issues with the transport
      
      // Collect the raw body
      let body = '';
      req.on('data', chunk => {
        body += chunk.toString();
      });
      
      req.on('end', async () => {
        try {
          const jsonRpcRequest = JSON.parse(body);
          logger.debug('Received JSON-RPC request:', { method: jsonRpcRequest.method });
          
          // Handle the request based on method
          let response;
          
          switch (jsonRpcRequest.method) {
            case 'initialize':
              // Negotiate protocol version for this client/request
              const negotiationResult = negotiateProtocolVersion(
                jsonRpcRequest.params?.protocolVersion,
                jsonRpcRequest.params?.clientInfo,
                req.get('user-agent'),
                req.headers
              );
              
              logProtocolNegotiation(negotiationResult, logger, 'HTTP_SERVER_INITIALIZE');
              
              response = {
                jsonrpc: '2.0',
                result: {
                  protocolVersion: negotiationResult.version,
                  capabilities: {
                    tools: {},
                    resources: {}
                  },
                  serverInfo: {
                    name: 'n8n-documentation-mcp',
                    version: PROJECT_VERSION
                  }
                },
                id: jsonRpcRequest.id
              };
              break;
              
            case 'tools/list':
              // Use the proper tool list that includes management tools when configured
              const tools = [...n8nDocumentationToolsFinal];
              
              // Add management tools if n8n API is configured
              if (isN8nApiConfigured()) {
                tools.push(...n8nManagementTools);
              }
              
              response = {
                jsonrpc: '2.0',
                result: {
                  tools
                },
                id: jsonRpcRequest.id
              };
              break;
              
            case 'tools/call':
              // Delegate to the MCP server
              const toolName = jsonRpcRequest.params?.name;
              const toolArgs = jsonRpcRequest.params?.arguments || {};
              
              try {
                const result = await mcpServer.executeTool(toolName, toolArgs);
                response = {
                  jsonrpc: '2.0',
                  result: {
                    content: [
                      {
                        type: 'text',
                        text: JSON.stringify(result, null, 2)
                      }
                    ]
                  },
                  id: jsonRpcRequest.id
                };
              } catch (error) {
                response = {
                  jsonrpc: '2.0',
                  error: {
                    code: -32603,
                    message: `Error executing tool ${toolName}: ${error instanceof Error ? error.message : 'Unknown error'}`
                  },
                  id: jsonRpcRequest.id
                };
              }
              break;
              
            default:
              response = {
                jsonrpc: '2.0',
                error: {
                  code: -32601,
                  message: `Method not found: ${jsonRpcRequest.method}`
                },
                id: jsonRpcRequest.id
              };
          }
          
          // Send response
          res.setHeader('Content-Type', 'application/json');
          res.json(response);
          
          const duration = Date.now() - startTime;
          logger.info('MCP request completed', { 
            duration,
            method: jsonRpcRequest.method,
            authMethod: authenticationMethod
          });
        } catch (error) {
          logger.error('Error processing request:', error);
          res.status(400).json({
            jsonrpc: '2.0',
            error: {
              code: -32700,
              message: 'Parse error',
              data: error instanceof Error ? error.message : 'Unknown error'
            },
            id: null
          });
        }
      });
    } catch (error) {
      logger.error('MCP request error:', error);
      
      if (!res.headersSent) {
        res.status(500).json({ 
          jsonrpc: '2.0',
          error: {
            code: -32603,
            message: 'Internal server error',
            data: process.env.NODE_ENV === 'development' 
              ? (error as Error).message 
              : undefined
          },
          id: null
        });
      }
    }
  });
  
  // 404 handler
  app.use((req, res) => {
    res.status(404).json({ 
      error: 'Not found',
      message: `Cannot ${req.method} ${req.path}`
    });
  });
  
  // Error handler
  app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
    logger.error('Express error handler:', err);
    
    if (!res.headersSent) {
      res.status(500).json({ 
        jsonrpc: '2.0',
        error: {
          code: -32603,
          message: 'Internal server error',
          data: process.env.NODE_ENV === 'development' ? err.message : undefined
        },
        id: null
      });
    }
  });
  
  const port = parseInt(process.env.PORT || '3000');
  const host = process.env.HOST || '0.0.0.0';
  
  expressServer = app.listen(port, host, () => {
    logger.info(`n8n MCP Fixed HTTP Server started`, { port, host });
    
    // Detect the base URL using our utility
    const baseUrl = getStartupBaseUrl(host, port);
    const endpoints = formatEndpointUrls(baseUrl);
    
    console.log(`n8n MCP Fixed HTTP Server running on ${host}:${port}`);
    console.log(`Health check: ${endpoints.health}`);
    console.log(`MCP endpoint: ${endpoints.mcp}`);
    console.log('\nPress Ctrl+C to stop the server');
    
    if (process.env.BASE_URL || process.env.PUBLIC_URL) {
      console.log(`\nPublic URL configured: ${baseUrl}`);
    } else if (process.env.TRUST_PROXY && Number(process.env.TRUST_PROXY) > 0) {
      console.log(`\nNote: TRUST_PROXY is enabled. URLs will be auto-detected from proxy headers.`);
    }
  });
  
  // Handle errors
  expressServer.on('error', (error: any) => {
    if (error.code === 'EADDRINUSE') {
      logger.error(`Port ${port} is already in use`);
      console.error(`ERROR: Port ${port} is already in use`);
      process.exit(1);
    } else {
      logger.error('Server error:', error);
      console.error('Server error:', error);
      process.exit(1);
    }
  });
  
  // Graceful shutdown handlers
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
  
  // Handle uncaught errors
  process.on('uncaughtException', (error) => {
    logger.error('Uncaught exception:', error);
    console.error('Uncaught exception:', error);
    shutdown();
  });
  
  process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled rejection:', reason);
    console.error('Unhandled rejection at:', promise, 'reason:', reason);
    shutdown();
  });
}

// Make executeTool public on the server
declare module './mcp/server' {
  interface N8NDocumentationMCPServer {
    executeTool(name: string, args: any): Promise<any>;
  }
}

// Start if called directly
// Check if this file is being run directly (not imported)
// In ES modules, we check import.meta.url against process.argv[1]
// But since we're transpiling to CommonJS, we use the require.main check
if (typeof require !== 'undefined' && require.main === module) {
  startFixedHTTPServer().catch(error => {
    logger.error('Failed to start Fixed HTTP server:', error);
    console.error('Failed to start Fixed HTTP server:', error);
    process.exit(1);
  });
}