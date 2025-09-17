#!/usr/bin/env node
/**
 * OAuth-enabled HTTP server for n8n-MCP that implements MCP Authorization specification
 * This implementation provides OAuth 2.1 with PKCE and Google OAuth integration
 */
import express from 'express';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { n8nDocumentationToolsFinal } from './mcp/tools';
import { n8nManagementTools } from './mcp/tools-n8n-manager';
import { N8NDocumentationMCPServer } from './mcp/server';
import { logger } from './utils/logger';
import { PROJECT_VERSION } from './utils/version';
import { isN8nApiConfigured } from './config/n8n-api';
import { oauthService } from './services/oauth-service';
import { googleOAuthService } from './services/google-oauth-service';
import dotenv from 'dotenv';
import crypto from 'crypto';
import { IncomingMessage } from 'http';
import { getStartupBaseUrl, formatEndpointUrls, detectBaseUrl } from './utils/url-detector';
import { 
  negotiateProtocolVersion, 
  logProtocolNegotiation,
  N8N_PROTOCOL_VERSION 
} from './utils/protocol-version';

dotenv.config();

let expressServer: any;

/**
 * Validate OAuth environment configuration
 */
function validateOAuthEnvironment(): { isValid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  // Check if Google OAuth is configured
  const googleConfig = googleOAuthService.getConfigStatus();
  if (!googleConfig.configured) {
    errors.push(`Google OAuth not configured. Missing: ${googleConfig.missing.join(', ')}`);
  }
  
  return {
    isValid: errors.length === 0,
    errors
  };
}

/**
 * Validate required environment variables
 */
function validateEnvironment() {
  const oauthValidation = validateOAuthEnvironment();
  
  if (!oauthValidation.isValid) {
    logger.warn('OAuth configuration warnings:', oauthValidation.errors);
    console.warn('⚠️ OAuth Configuration Warnings:');
    oauthValidation.errors.forEach(error => console.warn(`  - ${error}`));
    console.warn('\nSome OAuth features may not be available.\n');
  } else {
    logger.info('OAuth environment validation passed');
    console.log('✅ OAuth configuration is valid');
  }
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

export async function startOAuthHTTPServer() {
  validateEnvironment();
  
  const app = express();
  
  // Configure trust proxy for correct IP logging behind reverse proxies
  const trustProxy = process.env.TRUST_PROXY ? Number(process.env.TRUST_PROXY) : 0;
  if (trustProxy > 0) {
    app.set('trust proxy', trustProxy);
    logger.info(`Trust proxy enabled with ${trustProxy} hop(s)`);
  }
  
  // Body parser for OAuth endpoints (but not for MCP endpoint)
  app.use('/auth', express.urlencoded({ extended: true }));
  app.use('/auth', express.json());
  app.use('/.well-known', express.json());
  // Only apply body parsing to POST endpoints that need it
  app.use(['/token', '/register', '/revoke', '/introspect'], express.urlencoded({ extended: true }));
  app.use(['/token', '/register', '/revoke', '/introspect'], express.json());
  
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
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, Accept, MCP-Protocol-Version');
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
      contentLength: req.get('content-length')
    });
    next();
  });
  
  // Create a single persistent MCP server instance
  const mcpServer = new N8NDocumentationMCPServer();
  logger.info('Created persistent MCP server instance');

  // Get base URL for OAuth endpoints
  const getBaseUrl = (req: express.Request): string => {
    const port = parseInt(process.env.PORT || '3000');
    const host = process.env.HOST || '0.0.0.0';
    return detectBaseUrl(req, host, port);
  };

  // OAuth Authorization Server Metadata (RFC 8414)
  app.get('/.well-known/oauth-authorization-server', (req, res) => {
    const baseUrl = getBaseUrl(req);
    
    // Support MCP-Protocol-Version header as per spec
    const protocolVersion = req.get('MCP-Protocol-Version');
    if (protocolVersion) {
      logger.debug('OAuth metadata request with MCP protocol version', { protocolVersion });
    }
    
    res.json({
      issuer: baseUrl,
      authorization_endpoint: `${baseUrl}/authorize`,
      token_endpoint: `${baseUrl}/token`,
      registration_endpoint: `${baseUrl}/register`,
      revocation_endpoint: `${baseUrl}/revoke`,
      introspection_endpoint: `${baseUrl}/introspect`,
      scopes_supported: ['read', 'write'],
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      code_challenge_methods_supported: ['S256', 'plain'],
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
      service_documentation: 'https://github.com/czlonkowski/n8n-mcp',
      ui_locales_supported: ['en'],
      claims_supported: ['sub', 'email', 'name'],
      request_parameter_supported: false,
      request_uri_parameter_supported: false
    });
  });

  // Dynamic Client Registration (RFC 7591)
  app.post('/register', (req, res) => {
    try {
      const { 
        redirect_uris, 
        client_name, 
        client_type = 'public',
        grant_types = ['authorization_code', 'refresh_token'],
        token_endpoint_auth_method 
      } = req.body;
      
      if (!redirect_uris || !Array.isArray(redirect_uris) || redirect_uris.length === 0) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'redirect_uris is required and must be a non-empty array'
        });
      }
      
      // Validate redirect URIs according to MCP auth spec - MUST be HTTPS or localhost
      for (const uri of redirect_uris) {
        if (typeof uri !== 'string') {
          return res.status(400).json({
            error: 'invalid_redirect_uri',
            error_description: 'All redirect URIs must be strings'
          });
        }
        
        try {
          const parsed = new URL(uri);
          const isHttpsValid = parsed.protocol === 'https:';
          const isLocalhostValid = (parsed.protocol === 'http:') && 
            (parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1' || parsed.hostname === '::1');
            
          if (!isHttpsValid && !isLocalhostValid) {
            return res.status(400).json({
              error: 'invalid_redirect_uri',
              error_description: 'Redirect URIs must be HTTPS URLs or localhost HTTP URLs'
            });
          }
        } catch (error) {
          return res.status(400).json({
            error: 'invalid_redirect_uri',
            error_description: 'Invalid redirect URI format'
          });
        }
      }
      
      const client = oauthService.registerClient({
        redirect_uris,
        client_name,
        client_type: client_type as 'public' | 'confidential',
        grant_types,
        token_endpoint_auth_method
      });
      
      const response: any = {
        client_id: client.client_id,
        client_name: client.client_name,
        client_type: client.client_type,
        redirect_uris: client.redirect_uris,
        grant_types: client.grant_types,
        token_endpoint_auth_method: client.token_endpoint_auth_method,
        client_id_issued_at: Math.floor(client.created_at / 1000)
      };
      
      if (client.client_secret) {
        response.client_secret = client.client_secret;
        response.client_secret_expires_at = 0; // Never expires
      }
      
      res.status(201).json(response);
      return;
      
    } catch (error) {
      logger.error('Client registration error:', error);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Internal server error during client registration'
      });
      return;
    }
  });

  // Authorization Endpoint
  app.get('/authorize', (req, res) => {
    try {
      const {
        client_id,
        redirect_uri,
        response_type,
        scope = 'read',
        state,
        code_challenge,
        code_challenge_method = 'S256'
      } = req.query;
      
      // Validate required parameters
      if (!client_id || !redirect_uri || response_type !== 'code') {
        return         res.status(400).json({
          error: 'invalid_request',
          error_description: 'Missing or invalid required parameters'
        });
        return;
      }
      
      // Validate client and redirect URI
      if (!oauthService.validateRedirectUri(client_id as string, redirect_uri as string)) {
        return         res.status(400).json({
          error: 'invalid_client',
          error_description: 'Invalid client_id or redirect_uri'
        });
        return;
      }
      
      // Check if Google OAuth is configured for third-party auth
      if (!googleOAuthService.isConfigured()) {
        const errorUrl = new URL(redirect_uri as string);
        errorUrl.searchParams.set('error', 'server_error');
        errorUrl.searchParams.set('error_description', 'OAuth provider not configured');
        if (state) errorUrl.searchParams.set('state', state as string);
        res.redirect(errorUrl.toString());
        return;
      }
      
      // Generate Google OAuth URL for third-party authorization
      const googleAuthUrl = googleOAuthService.generateAuthUrl(
        client_id as string,
        redirect_uri as string,
        code_challenge as string,
        code_challenge_method as string,
        (scope as string).split(' '),
        state as string // Pass through the state parameter
      );
      
      // Redirect to Google OAuth
      res.redirect(googleAuthUrl);
      return;
      
    } catch (error) {
      logger.error('Authorization endpoint error:', error);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Internal server error'
      });
      return;
    }
  });

  // Google OAuth Callback
  app.get('/auth/google/callback', async (req, res) => {
    try {
      const { code, state, error } = req.query;
      
      if (error) {
        logger.error('Google OAuth error:', error);
        res.status(400).json({
          error: 'access_denied',
          error_description: `Google OAuth error: ${error}`
        });
        return;
      }
      
      if (!code || !state) {
        res.status(400).json({
          error: 'invalid_request',
          error_description: 'Missing authorization code or state'
        });
        return;
      }
      
      // Handle Google OAuth callback
      const result = await googleOAuthService.handleCallback(code as string, state as string);
      
      if (!result) {
        res.status(400).json({
          error: 'access_denied',
          error_description: 'Google OAuth authentication failed'
        });
        return;
      }
      
      const { authState, userInfo } = result;
      
      // Store user info and generate authorization code for original client
      const userId = oauthService.storeGoogleUser(userInfo);
      const authCode = oauthService.generateAuthorizationCode(
        authState.original_client_id,
        authState.original_redirect_uri,
        userId,
        authState.scopes,
        authState.code_challenge,
        authState.code_challenge_method
      );
      
      // Redirect back to original client with authorization code
      const redirectUrl = new URL(authState.original_redirect_uri);
      redirectUrl.searchParams.set('code', authCode);
      // Always pass through the original state parameter if provided
      if (authState.original_state) {
        redirectUrl.searchParams.set('state', authState.original_state);
      }
      
      res.redirect(redirectUrl.toString());
      
    } catch (error) {
      logger.error('Google OAuth callback error:', error);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Internal server error during OAuth callback'
      });
    }
  });

  // Token Revocation Endpoint (RFC 7009)
  app.post('/revoke', (req, res) => {
    try {
      const { token, token_type_hint } = req.body;
      
      if (!token) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Missing required parameter: token'
        });
      }
      
      // Try to revoke as access token first, then refresh token
      let revoked = false;
      const accessToken = oauthService.validateAccessToken(token);
      if (accessToken) {
        // Would need to implement revocation in oauth service
        logger.info('Access token revoked', { client_id: accessToken.client_id });
        revoked = true;
      }
      
      // According to RFC 7009, return 200 OK even if token was not found
      res.status(200).json({});
      return;
      
    } catch (error) {
      logger.error('Token revocation error:', error);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Internal server error'
      });
      return;
    }
  });

  // Token Introspection Endpoint (RFC 7662)
  app.post('/introspect', (req, res) => {
    try {
      const { token } = req.body;
      
      if (!token) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Missing required parameter: token'
        });
      }
      
      const accessToken = oauthService.validateAccessToken(token);
      
      if (!accessToken) {
        // Token is not active
        res.json({ active: false });
        return;
      }
      
      // Token is active, return token info
      res.json({
        active: true,
        client_id: accessToken.client_id,
        username: accessToken.user_id,
        scope: accessToken.scopes.join(' '),
        token_type: 'Bearer',
        exp: Math.floor(accessToken.expires_at / 1000),
        iat: Math.floor(accessToken.created_at / 1000)
      });
      return;
      
    } catch (error) {
      logger.error('Token introspection error:', error);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Internal server error'
      });
      return;
    }
  });

  // Token Endpoint
  app.post('/token', (req, res) => {
    try {
      const { 
        grant_type, 
        code, 
        client_id, 
        redirect_uri, 
        code_verifier,
        refresh_token 
      } = req.body;
      
      if (grant_type === 'authorization_code') {
        // Authorization code grant
        if (!code || !client_id || !redirect_uri) {
          return res.status(400).json({
            error: 'invalid_request',
            error_description: 'Missing required parameters for authorization_code grant'
          });
        }
        
        const accessToken = oauthService.exchangeAuthorizationCode(
          code,
          client_id,
          redirect_uri,
          code_verifier
        );
        
        if (!accessToken) {
          return res.status(400).json({
            error: 'invalid_grant',
            error_description: 'Invalid or expired authorization code'
          });
        }
        
        res.json({
          access_token: accessToken.access_token,
          token_type: accessToken.token_type,
          expires_in: accessToken.expires_in,
          refresh_token: accessToken.refresh_token,
          scope: accessToken.scopes.join(' ')
        });
        return;
        
      } else if (grant_type === 'refresh_token') {
        // Refresh token grant
        if (!refresh_token || !client_id) {
          return res.status(400).json({
            error: 'invalid_request',
            error_description: 'Missing required parameters for refresh_token grant'
          });
        }
        
        const newAccessToken = oauthService.refreshAccessToken(refresh_token, client_id);
        
        if (!newAccessToken) {
          return res.status(400).json({
            error: 'invalid_grant',
            error_description: 'Invalid or expired refresh token'
          });
        }
        
        res.json({
          access_token: newAccessToken.access_token,
          token_type: newAccessToken.token_type,
          expires_in: newAccessToken.expires_in,
          refresh_token: newAccessToken.refresh_token,
          scope: newAccessToken.scopes.join(' ')
        });
        return;
        
      } else {
        res.status(400).json({
          error: 'unsupported_grant_type',
          error_description: `Grant type '${grant_type}' is not supported`
        });
        return;
      }
      
    } catch (error) {
      logger.error('Token endpoint error:', error);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Internal server error'
      });
      return;
    }
  });

  // Default OAuth endpoints as per MCP auth spec section "Fallbacks for Servers without Metadata Discovery"
  // The /authorize, /token, and /register endpoints above serve as the default endpoints

  // Root endpoint with API information
  app.get('/', (req, res) => {
    const baseUrl = getBaseUrl(req);
    const endpoints = formatEndpointUrls(baseUrl);
    
    res.json({
      name: 'n8n Documentation MCP Server',
      version: PROJECT_VERSION,
      description: 'Model Context Protocol server with OAuth 2.1 authorization',
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
        },
        oauth_metadata: {
          url: `${baseUrl}/.well-known/oauth-authorization-server`,
          method: 'GET',
          description: 'OAuth Authorization Server Metadata'
        },
        authorize: {
          url: `${baseUrl}/authorize`,
          method: 'GET',
          description: 'OAuth authorization endpoint'
        },
        token: {
          url: `${baseUrl}/token`,
          method: 'POST',
          description: 'OAuth token endpoint'
        },
        register: {
          url: `${baseUrl}/register`,
          method: 'POST',
          description: 'OAuth dynamic client registration'
        },
        revoke: {
          url: `${baseUrl}/revoke`,
          method: 'POST',
          description: 'OAuth token revocation'
        },
        introspect: {
          url: `${baseUrl}/introspect`,
          method: 'POST',
          description: 'OAuth token introspection'
        }
      },
      authentication: {
        type: 'OAuth 2.1',
        authorization_endpoint: `${baseUrl}/authorize`,
        token_endpoint: `${baseUrl}/token`,
        registration_endpoint: `${baseUrl}/register`,
        metadata_endpoint: `${baseUrl}/.well-known/oauth-authorization-server`,
        required_for: ['POST /mcp'],
        third_party_provider: googleOAuthService.isConfigured() ? 'Google' : 'Not configured'
      },
      documentation: 'https://github.com/czlonkowski/n8n-mcp'
    });
  });

  // Health check endpoint
  app.get('/health', (req, res) => {
    const oauthStats = oauthService.getStats();
    const googleStats = googleOAuthService.getStats();
    
    res.json({ 
      status: 'ok', 
      mode: 'oauth-enabled',
      version: PROJECT_VERSION,
      uptime: Math.floor(process.uptime()),
      memory: {
        used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
        total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024),
        unit: 'MB'
      },
      oauth: {
        service: oauthStats,
        google: googleStats
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

  // Main MCP endpoint - handle each request with OAuth authentication
  app.post('/mcp', async (req: express.Request, res: express.Response): Promise<void> => {
    const startTime = Date.now();
    
    // OAuth token authentication
    const authHeader = req.headers.authorization;
    
    // Check if Authorization header is missing
    if (!authHeader) {
      logger.warn('MCP request failed: Missing Authorization header', { 
        ip: req.ip,
        userAgent: req.get('user-agent'),
        reason: 'no_auth_header'
      });
      res.status(401).json({ 
        jsonrpc: '2.0',
        error: {
          code: -32001,
          message: 'Unauthorized - OAuth Bearer token required'
        },
        id: null
      });
      return;
    }
    
    // Check if Authorization header has Bearer prefix
    if (!authHeader.startsWith('Bearer ')) {
      logger.warn('MCP request failed: Invalid Authorization header format', { 
        ip: req.ip,
        userAgent: req.get('user-agent'),
        reason: 'invalid_auth_format'
      });
      res.status(401).json({ 
        jsonrpc: '2.0',
        error: {
          code: -32001,
          message: 'Unauthorized - Bearer token format required'
        },
        id: null
      });
      return;
    }
    
    // Extract token and validate with OAuth service
    const token = authHeader.slice(7).trim();
    const accessToken = oauthService.validateAccessToken(token);
    
    if (!accessToken) {
      logger.warn('MCP request failed: Invalid or expired OAuth token', { 
        ip: req.ip,
        userAgent: req.get('user-agent'),
        reason: 'invalid_oauth_token'
      });
      res.status(401).json({ 
        jsonrpc: '2.0',
        error: {
          code: -32001,
          message: 'Unauthorized - Invalid or expired OAuth token'
        },
        id: null
      });
      return;
    }
    
    // Log successful authentication
    logger.info('MCP request authenticated', {
      client_id: accessToken.client_id,
      user_id: accessToken.user_id,
      scopes: accessToken.scopes,
      ip: req.ip
    });
    
    try {
      // Instead of using StreamableHTTPServerTransport, we'll handle the request directly
      // This avoids the initialization issues with the transport
      
      // Collect the raw body
      let body = '';
      const chunks: Buffer[] = [];
      
      (req as any).on('data', (chunk: Buffer) => {
        chunks.push(chunk);
      });
      
      (req as any).on('end', async () => {
        body = Buffer.concat(chunks).toString('utf8');
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
            client_id: accessToken.client_id,
            user_id: accessToken.user_id
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
    logger.info(`n8n MCP OAuth HTTP Server started`, { port, host });
    
    // Detect the base URL using our utility
    const baseUrl = getStartupBaseUrl(host, port);
    const endpoints = formatEndpointUrls(baseUrl);
    
    console.log(`\n✅ n8n MCP OAuth HTTP Server running on ${host}:${port}`);
    console.log(`Health check: ${endpoints.health}`);
    console.log(`MCP endpoint: ${endpoints.mcp}`);
    console.log(`OAuth metadata: ${baseUrl}/.well-known/oauth-authorization-server`);
    console.log(`OAuth authorization: ${baseUrl}/authorize`);
    console.log(`OAuth token: ${baseUrl}/token`);
    console.log(`OAuth registration: ${baseUrl}/register`);
    
    // Show OAuth configuration status
    const googleConfig = googleOAuthService.getConfigStatus();
    if (googleConfig.configured) {
      console.log('\n✅ Google OAuth configured and ready');
    } else {
      console.log(`\n⚠️  Google OAuth not fully configured. Missing: ${googleConfig.missing.join(', ')}`);
    }
    
    console.log('\nAuthentication: OAuth 2.1 with PKCE required');
    console.log('Third-party provider: Google OAuth');
    console.log('\nPress Ctrl+C to stop the server\n');
    
    if (process.env.BASE_URL || process.env.PUBLIC_URL) {
      console.log(`Public URL configured: ${baseUrl}`);
    } else if (process.env.TRUST_PROXY && Number(process.env.TRUST_PROXY) > 0) {
      console.log(`Note: TRUST_PROXY is enabled. URLs will be auto-detected from proxy headers.`);
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

// Export the old function name for backward compatibility
export const startFixedHTTPServer = startOAuthHTTPServer;

// Start if called directly
// Check if this file is being run directly (not imported)
// In ES modules, we check import.meta.url against process.argv[1]
// But since we're transpiling to CommonJS, we use the require.main check
if (typeof require !== 'undefined' && require.main === module) {
  startOAuthHTTPServer().catch(error => {
    logger.error('Failed to start OAuth HTTP server:', error);
    console.error('Failed to start OAuth HTTP server:', error);
    process.exit(1);
  });
}