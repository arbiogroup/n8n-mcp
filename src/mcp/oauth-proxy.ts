import { Request, Response } from "express";
import { logger } from "../utils/logger";
import { JWTService } from "../services/jwt-service";
import { OAuthConfig, GoogleUser } from "../config/oauth";
import crypto from "crypto";

// Extend Express Session interface
declare module 'express-session' {
  interface SessionData {
    authRequest?: AuthorizationRequest;
    authCode?: string;
    user?: GoogleUser;
  }
}

/**
 * OAuth Proxy for MCP Client Dynamic Registration
 * This implements OAuth 2.0 Dynamic Client Registration (RFC 7591) to enable
 * seamless MCP client connections without manual configuration
 */
export class MCPOAuthProxy {
  private jwtService: JWTService;
  private config: OAuthConfig;
  private registeredClients: Map<string, MCPClientRegistration> = new Map();

  constructor(jwtService: JWTService, config: OAuthConfig) {
    this.jwtService = jwtService;
    this.config = config;
  }

  /**
   * Dynamic Client Registration endpoint (RFC 7591)
   * Allows MCP clients to register themselves automatically
   */
  registerClient = (req: Request, res: Response): void => {
    try {
      const clientMetadata = req.body;
      
      // Validate required fields
      if (!clientMetadata.client_name || !clientMetadata.redirect_uris) {
        res.status(400).json({
          error: "invalid_client_metadata",
          error_description: "client_name and redirect_uris are required"
        });
        return;
      }

      // Generate client credentials
      const clientId = this.generateClientId();
      const clientSecret = this.generateClientSecret();
      
      const registration: MCPClientRegistration = {
        client_id: clientId,
        client_secret: clientSecret,
        client_id_issued_at: Math.floor(Date.now() / 1000),
        client_secret_expires_at: 0, // No expiration for MCP clients
        client_name: clientMetadata.client_name,
        redirect_uris: clientMetadata.redirect_uris,
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        scope: "openid email profile mcp",
        token_endpoint_auth_method: "client_secret_post",
        application_type: "native", // MCP clients are typically native applications
        created_at: new Date().toISOString(),
        last_used: null
      };

      this.registeredClients.set(clientId, registration);

      logger.info("MCP client registered", {
        clientId,
        clientName: clientMetadata.client_name,
        redirectUris: clientMetadata.redirect_uris
      });

      res.status(201).json(registration);
    } catch (error) {
      logger.error("Client registration error", { error });
      res.status(500).json({
        error: "server_error",
        error_description: "Internal server error during client registration"
      });
    }
  };

  /**
   * OAuth Authorization endpoint with MCP-specific handling
   */
  authorize = (req: Request, res: Response): void => {
    const {
      client_id,
      redirect_uri,
      response_type,
      scope,
      state,
      code_challenge,
      code_challenge_method
    } = req.query;

    // Validate client
    const client = this.registeredClients.get(client_id as string);
    if (!client) {
      res.status(400).json({
        error: "invalid_client",
        error_description: "Unknown client_id"
      });
      return;
    }

    // Validate redirect URI
    if (!client.redirect_uris.includes(redirect_uri as string)) {
      res.status(400).json({
        error: "invalid_request",
        error_description: "Invalid redirect_uri"
      });
      return;
    }

    // Store authorization request for callback
    const authRequest: AuthorizationRequest = {
      client_id: client_id as string,
      redirect_uri: redirect_uri as string,
      response_type: response_type as string,
      scope: scope as string,
      state: state as string,
      code_challenge: code_challenge as string,
      code_challenge_method: code_challenge_method as string,
      created_at: new Date().toISOString()
    };

    // Store in session for callback processing
    req.session!.authRequest = authRequest;

    // Redirect to Google OAuth with MCP context
    const googleAuthUrl = this.buildGoogleAuthUrlWithMCPContext(authRequest);
    res.redirect(googleAuthUrl);
  };

  /**
   * OAuth Token endpoint for MCP clients
   */
  token = async (req: Request, res: Response): Promise<void> => {
    try {
      const { grant_type, code, redirect_uri, client_id, client_secret, refresh_token } = req.body;

      // Validate client credentials
      const client = this.registeredClients.get(client_id);
      if (!client || client.client_secret !== client_secret) {
        res.status(401).json({
          error: "invalid_client",
          error_description: "Invalid client credentials"
        });
        return;
      }

      if (grant_type === "authorization_code") {
        // Exchange authorization code for tokens
        const authCode = req.session!.authCode;
        if (!authCode || authCode !== code) {
          res.status(400).json({
            error: "invalid_grant",
            error_description: "Invalid authorization code"
          });
          return;
        }

        const user = req.session!.user as GoogleUser;
        if (!user) {
          res.status(400).json({
            error: "invalid_grant",
            error_description: "No user information available"
          });
          return;
        }

        // Generate tokens
        const tokenPair = this.jwtService.generateTokenPair(user);
        
        // Update client last used
        client.last_used = new Date().toISOString();

        res.json({
          access_token: tokenPair.accessToken,
          token_type: "Bearer",
          expires_in: tokenPair.expiresIn,
          refresh_token: tokenPair.refreshToken,
          scope: "openid email profile mcp",
          // MCP-specific information
          mcp: {
            server_url: this.getMCPServerUrl(req),
            connection_instructions: this.getConnectionInstructions(req),
            supported_transports: ["http", "websocket", "stdio"]
          }
        });

        // Clear session data
        delete req.session!.authCode;
        delete req.session!.user;
        delete req.session!.authRequest;

      } else if (grant_type === "refresh_token") {
        // Handle token refresh
        const newTokens = this.jwtService.refreshToken(refresh_token);
        if (!newTokens) {
          res.status(400).json({
            error: "invalid_grant",
            error_description: "Invalid refresh token"
          });
          return;
        }

        res.json({
          access_token: newTokens.accessToken,
          token_type: "Bearer",
          expires_in: this.jwtService.parseExpirationTime(this.config.jwt.expiresIn),
          refresh_token: newTokens.refreshToken,
          scope: "openid email profile mcp"
        });
      } else {
        res.status(400).json({
          error: "unsupported_grant_type",
          error_description: "Only authorization_code and refresh_token are supported"
        });
      }
    } catch (error) {
      logger.error("Token endpoint error", { error });
      res.status(500).json({
        error: "server_error",
        error_description: "Internal server error"
      });
    }
  };

  /**
   * MCP Client Discovery endpoint
   * Provides connection information for different MCP clients
   */
  discover = (req: Request, res: Response): void => {
    const baseUrl = this.getBaseUrl(req);
    
    res.json({
      issuer: baseUrl,
      authorization_endpoint: `${baseUrl}/oauth/authorize`,
      token_endpoint: `${baseUrl}/oauth/token`,
      registration_endpoint: `${baseUrl}/oauth/register`,
      mcp_endpoint: `${baseUrl}/mcp`,
      supported_grant_types: ["authorization_code", "refresh_token"],
      supported_response_types: ["code"],
      supported_scopes: ["openid", "email", "profile", "mcp"],
      mcp_clients: {
        claude_desktop: {
          name: "Claude Desktop",
          connection_type: "stdio",
          setup_instructions: "Add this server to your Claude Desktop configuration",
          config_example: {
            command: "npx",
            args: ["-y", "mcp-remote", baseUrl, "--header", "Authorization: Bearer YOUR_TOKEN"]
          }
        },
        windsurf: {
          name: "Windsurf",
          connection_type: "http",
          setup_instructions: "Add this server to your Windsurf MCP configuration",
          config_example: {
            url: `${baseUrl}/mcp`,
            headers: {
              "Authorization": "Bearer YOUR_TOKEN"
            }
          }
        },
        custom_client: {
          name: "Custom MCP Client",
          connection_type: "any",
          setup_instructions: "Use the OAuth flow to get tokens, then connect to the MCP endpoint",
          oauth_flow: {
            step1: "Register your client at /oauth/register",
            step2: "Redirect user to /oauth/authorize",
            step3: "Exchange code for tokens at /oauth/token",
            step4: "Use access_token to connect to /mcp"
          }
        }
      }
    });
  };

  /**
   * Handle OAuth callback with MCP context
   */
  handleCallback = async (req: Request, res: Response): Promise<void> => {
    try {
      const user = req.user as GoogleUser;
      const authRequest = req.session!.authRequest as AuthorizationRequest;

      if (!user || !authRequest) {
        res.status(400).json({
          error: "invalid_request",
          error_description: "Missing user or authorization request"
        });
        return;
      }

      // Validate domain if required
      if (!this.jwtService.validateDomain(user)) {
        res.status(403).json({
          error: "access_denied",
          error_description: "Domain not authorized"
        });
        return;
      }

      // Generate authorization code
      const authCode = this.generateAuthCode();
      req.session!.authCode = authCode;
      req.session!.user = user;

      // Redirect back to client with authorization code
      const redirectUri = new URL(authRequest.redirect_uri);
      redirectUri.searchParams.set("code", authCode);
      if (authRequest.state) {
        redirectUri.searchParams.set("state", authRequest.state);
      }

      res.redirect(redirectUri.toString());
    } catch (error) {
      logger.error("OAuth callback error", { error });
      res.status(500).json({
        error: "server_error",
        error_description: "Internal server error"
      });
    }
  };

  private buildGoogleAuthUrlWithMCPContext(authRequest: AuthorizationRequest): string {
    const state = JSON.stringify({
      mcp_client: authRequest.client_id,
      original_state: authRequest.state,
      timestamp: Date.now()
    });

    const params = new URLSearchParams({
      client_id: this.config.google.clientId,
      redirect_uri: this.config.google.callbackUrl,
      scope: 'openid email profile',
      response_type: 'code',
      state: state
    });

    return `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
  }

  private getMCPServerUrl(req: Request): string {
    const baseUrl = this.getBaseUrl(req);
    return `${baseUrl}/mcp`;
  }

  private getBaseUrl(req: Request): string {
    const protocol = req.get('x-forwarded-proto') || req.protocol;
    const host = req.get('x-forwarded-host') || req.get('host');
    return `${protocol}://${host}`;
  }

  private getConnectionInstructions(req: Request): any {
    const baseUrl = this.getBaseUrl(req);
    
    return {
      claude_desktop: {
        description: "For Claude Desktop users",
        steps: [
          "1. Complete OAuth flow to get access token",
          "2. Add to Claude Desktop config:",
          `   "mcpServers": {`,
          `     "n8n-docs": {`,
          `       "command": "npx",`,
          `       "args": ["-y", "mcp-remote", "${baseUrl}/mcp", "--header", "Authorization: Bearer YOUR_TOKEN"]`,
          `     }`,
          `   }`
        ]
      },
      windsurf: {
        description: "For Windsurf users",
        steps: [
          "1. Complete OAuth flow to get access token",
          "2. Add to Windsurf MCP settings:",
          `   URL: ${baseUrl}/mcp`,
          `   Headers: {"Authorization": "Bearer YOUR_TOKEN"}`
        ]
      }
    };
  }

  private generateClientId(): string {
    return `mcp_${crypto.randomBytes(16).toString('hex')}`;
  }

  private generateClientSecret(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  private generateAuthCode(): string {
    return crypto.randomBytes(32).toString('hex');
  }
}

interface MCPClientRegistration {
  client_id: string;
  client_secret: string;
  client_id_issued_at: number;
  client_secret_expires_at: number;
  client_name: string;
  redirect_uris: string[];
  grant_types: string[];
  response_types: string[];
  scope: string;
  token_endpoint_auth_method: string;
  application_type: string;
  created_at: string;
  last_used: string | null;
}

interface AuthorizationRequest {
  client_id: string;
  redirect_uri: string;
  response_type: string;
  scope: string;
  state: string;
  code_challenge?: string;
  code_challenge_method?: string;
  created_at: string;
}
