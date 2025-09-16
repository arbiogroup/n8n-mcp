import { Router, Request, Response } from 'express';
import { getOAuthConfig } from '../config/oauth';
import { PROJECT_VERSION } from '../utils/version';
import { logger } from '../utils/logger';

export function createDiscoveryRouter(): Router {
  const router = Router();
  const config = getOAuthConfig();

  /**
   * GET /.well-known/oauth-authorization-server
   * 
   * OAuth 2.1 Authorization Server Metadata (RFC 8414)
   * Provides discovery information for OAuth clients
   */
  router.get('/.well-known/oauth-authorization-server', (req: Request, res: Response) => {
    try {
      const baseUrl = config.OAUTH_ISSUER;
      const mcpProtocolVersion = req.get('MCP-Protocol-Version');
      
      // Log MCP protocol version if provided
      if (mcpProtocolVersion) {
        logger.info('MCP OAuth discovery request', { 
          mcpProtocolVersion,
          userAgent: req.get('user-agent')
        });
      }

      const metadata = {
        // Core OAuth 2.1 metadata
        issuer: baseUrl,
        authorization_endpoint: `${baseUrl}/authorize`,
        token_endpoint: `${baseUrl}/token`,
        
        // Supported features
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code', 'client_credentials', 'refresh_token'],
        code_challenge_methods_supported: ['S256'],
        
        // Authentication methods
        token_endpoint_auth_methods_supported: [
          'client_secret_basic',
          'client_secret_post',
          'none' // For public clients
        ],
        
        // Optional endpoints
        revocation_endpoint: `${baseUrl}/revoke`,
        introspection_endpoint: `${baseUrl}/introspect`,
        registration_endpoint: `${baseUrl}/register`,
        
        // Dynamic client registration support  
        client_registration_endpoint: `${baseUrl}/register`,
        client_registration_authn_methods_supported: ['none'], // Public registration
        
        // JWKS endpoint (for JWT token verification)
        jwks_uri: `${baseUrl}/.well-known/jwks.json`,
        
        // Free scope mode - accept any scopes
        scopes_supported: ['*'], // Indicates all scopes are supported
        
        // OAuth 2.1 specific features
        require_request_uri_registration: false,
        require_signed_request_object: false,
        
        // PKCE is required for OAuth 2.1 (note: already defined above)
        
        // Additional metadata
        service_documentation: 'https://github.com/czlonkowski/n8n-mcp/docs/oauth',
        ui_locales_supported: ['en'],
        
        // Server information
        op_policy_uri: `${baseUrl}/privacy`,
        op_tos_uri: `${baseUrl}/terms`,
        
        // Response modes
        response_modes_supported: ['query', 'fragment'],
        
        // Claims (for OpenID Connect compatibility)
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['HS256'],
        
        // Custom extensions
        'n8n_mcp_version': PROJECT_VERSION,
        'n8n_mcp_features': [
          'node_documentation',
          'workflow_management',
          'google_oauth_integration'
        ]
      };

      logger.debug('OAuth authorization server metadata requested');

      res.json(metadata);
    } catch (error) {
      logger.error('Error serving OAuth metadata:', error);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Failed to retrieve server metadata'
      });
    }
  });

  /**
   * GET /.well-known/jwks.json
   * 
   * JSON Web Key Set for JWT token verification
   * Currently returns empty set since we use opaque tokens,
   * but this is here for future JWT implementation
   */
  router.get('/.well-known/jwks.json', (req: Request, res: Response) => {
    try {
      // For now, return empty JWKS since we're using opaque tokens
      // In the future, when we implement proper JWT tokens, we'll add keys here
      const jwks = {
        keys: [
          // Future JWT signing keys will go here
          // Example structure:
          // {
          //   kty: 'RSA',
          //   use: 'sig',
          //   alg: 'RS256',
          //   kid: 'main-key-2024',
          //   n: '...',  // RSA public key modulus
          //   e: 'AQAB'  // RSA public key exponent
          // }
        ]
      };

      logger.debug('JWKS requested');

      res.json(jwks);
    } catch (error) {
      logger.error('Error serving JWKS:', error);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Failed to retrieve JWKS'
      });
    }
  });

  /**
   * GET /.well-known/openid_configuration
   * 
   * OpenID Connect Discovery (optional)
   * Provides compatibility with OpenID Connect clients
   */
  router.get('/.well-known/openid_configuration', (req: Request, res: Response) => {
    try {
      const baseUrl = config.OAUTH_ISSUER;

      const openidConfig = {
        // OpenID Connect Core
        issuer: baseUrl,
        authorization_endpoint: `${baseUrl}/authorize`,
        token_endpoint: `${baseUrl}/token`,
        userinfo_endpoint: `${baseUrl}/oauth/userinfo`,
        jwks_uri: `${baseUrl}/.well-known/jwks.json`,
        
        // Supported features
        response_types_supported: ['code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['HS256'],
        
        // Free scope mode - accept any scopes (including OpenID Connect scopes)
        scopes_supported: ['*', 'openid', 'profile', 'email'], // Wildcard indicates all scopes supported
        
        // Claims
        claims_supported: [
          'sub',
          'email',
          'email_verified',
          'name',
          'picture',
          'iss',
          'aud',
          'exp',
          'iat'
        ],
        
        // Additional endpoints
        revocation_endpoint: `${baseUrl}/revoke`,
        introspection_endpoint: `${baseUrl}/introspect`,
        registration_endpoint: `${baseUrl}/register`,
        
        // PKCE support
        code_challenge_methods_supported: ['S256'],
        
        // Server info
        service_documentation: 'https://github.com/czlonkowski/n8n-mcp/docs/oauth'
      };

      logger.debug('OpenID Connect configuration requested');

      res.json(openidConfig);
    } catch (error) {
      logger.error('Error serving OpenID Connect configuration:', error);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Failed to retrieve OpenID Connect configuration'
      });
    }
  });

  /**
   * GET /oauth/userinfo
   * 
   * UserInfo endpoint (OpenID Connect)
   * Returns user information for authenticated requests
   */
  router.get('/oauth/userinfo', async (req: Request, res: Response): Promise<any> => {
    try {
      const authHeader = req.headers.authorization;
      
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
          error: 'invalid_token',
          error_description: 'Missing or invalid Authorization header'
        });
      }

      // For now, return basic user info structure
      // This would be implemented with proper token validation
      const userInfo = {
        sub: 'user@arbio.io', // Subject (user identifier)
        email: 'user@arbio.io',
        email_verified: true,
        name: 'OAuth User',
        picture: 'https://example.com/avatar.jpg',
        iss: config.OAUTH_ISSUER,
        aud: 'oauth-client'
      };

      logger.debug('UserInfo requested');

      res.json(userInfo);
    } catch (error) {
      logger.error('Error serving UserInfo:', error);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Failed to retrieve user information'
      });
    }
  });

  return router;
}
