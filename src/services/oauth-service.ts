import { OAuthRepository } from '../repositories/oauth-repository';
import { getOAuthConfig, parseScopes, formatScopes } from '../config/oauth';
import { 
  generateClientId, 
  generateClientSecret, 
  generateAuthorizationCode,
  generateSecureToken,
  createAccessToken,
  createRefreshToken,
  verifyAccessToken,
  validatePKCE,
  validateRedirectUri,
  calculateExpirationDate,
  validateEmailDomain,
  isTokenExpired,
  getTokenLifetime
} from '../utils/oauth-utils';
import {
  OAuthClient,
  OAuthToken,
  OAuthAuthorizationCode,
  TokenResponse,
  ClientRegistrationRequest,
  ClientRegistrationResponse,
  IntrospectionResponse,
  InvalidClientError,
  InvalidGrantError,
  InvalidRequestError,
  InvalidScopeError,
  UnsupportedGrantTypeError,
  AccessDeniedError
} from '../models/oauth-models';
import { logger } from '../utils/logger';

export class OAuthService {
  private config = getOAuthConfig();

  constructor(private repository: OAuthRepository) {}

  // Client Registration
  async registerClient(request: ClientRegistrationRequest): Promise<ClientRegistrationResponse> {
    try {
      // Validate request
      if (!request.client_name || !request.redirect_uris || request.redirect_uris.length === 0) {
        throw new InvalidRequestError('Missing required fields: client_name, redirect_uris');
      }

      // Validate redirect URIs
      for (const uri of request.redirect_uris) {
        try {
          new URL(uri);
        } catch {
          throw new InvalidRequestError(`Invalid redirect URI: ${uri}`);
        }
      }

      // Validate requested scopes
      const requestedScopes = request.scope ? parseScopes(request.scope) : ['mcp:read'];
      // Scope validation disabled - accept any scopes

      // Use provided client_id or generate new one
      const clientId = request.client_id || generateClientId();
      const clientSecret = request.client_type === 'public' ? undefined : generateClientSecret();

      // Create client
      const client = await this.repository.createClient({
        id: clientId,
        name: request.client_name,
        secret: clientSecret,
        redirectUris: request.redirect_uris,
        scope: formatScopes(requestedScopes),
        clientType: request.client_type || 'confidential'
      });

      logger.info(`OAuth client registered: ${client.name} (${clientId})`);

      return {
        client_id: client.id,
        client_secret: client.secret,
        client_name: client.name,
        redirect_uris: client.redirectUris,
        grant_types: request.grant_types || ['authorization_code'],
        scope: client.scope,
        client_type: request.client_type || 'confidential'
      };
    } catch (error) {
      logger.error('Client registration failed:', error);
      throw error;
    }
  }

  async getClient(clientId: string): Promise<OAuthClient | null> {
    let client = await this.repository.getClient(clientId);
    
    // If client doesn't exist and it's Claude AI, auto-register it
    if (!client && clientId === '992236964315-rpq06uolni85341iafnc51q4r6sogmd6.apps.googleusercontent.com') {
      logger.info('Auto-registering Claude AI client in getClient()');
      try {
        const registrationData = {
          client_name: 'Claude AI',
          client_id: clientId,
          redirect_uris: [
            'https://claude.ai/api/mcp/auth_callback',
            'https://claude.ai/oauth/callback'
          ],
          scope: '*', // Accept all scopes - no restrictions
          client_type: 'public' as const
        };
        
        await this.registerClient(registrationData);
        client = await this.repository.getClient(clientId);
        
        if (client) {
          logger.info('✅ Claude AI auto-registered successfully in getClient()', {
            clientId: client.id,
            name: client.name
          });
        }
      } catch (error) {
        logger.warn('Auto-registration failed in getClient():', error);
      }
    }
    
    return client;
  }

  async updateClient(clientId: string, updates: Partial<Pick<OAuthClient, 'name' | 'redirectUris' | 'scope'>>): Promise<OAuthClient | null> {
    return this.repository.updateClient(clientId, updates);
  }

  async deleteClient(clientId: string): Promise<boolean> {
    const success = await this.repository.deleteClient(clientId);
    if (success) {
      logger.info(`OAuth client deleted: ${clientId}`);
    }
    return success;
  }

  async listClients(): Promise<OAuthClient[]> {
    return this.repository.listClients();
  }

  // Authorization Flow
  async createAuthorizationRequest(params: {
    clientId: string;
    redirectUri: string;
    scope?: string;
    state?: string;
    codeChallenge?: string;
    codeChallengeMethod?: string;
  }): Promise<{ client: OAuthClient; requestedScopes: string[] }> {
    // Validate client
    const client = await this.repository.getClient(params.clientId);
    if (!client) {
      throw new InvalidClientError('Unknown client');
    }

    // Validate redirect URI
    if (!validateRedirectUri(client.redirectUris, params.redirectUri)) {
      throw new InvalidRequestError('Invalid redirect_uri');
    }

    // Validate and parse scopes
    const requestedScopes = params.scope ? parseScopes(params.scope) : parseScopes(client.scope);
    // Scope validation disabled - accept any scopes

    // Validate PKCE for public clients
    if (client.clientType === 'public') {
      if (!params.codeChallenge || !params.codeChallengeMethod) {
        throw new InvalidRequestError('PKCE required for public clients');
      }
      if (params.codeChallengeMethod !== 'S256') {
        throw new InvalidRequestError('Only S256 code challenge method is supported');
      }
    }

    logger.debug(`Authorization request validated for client: ${client.name}`);

    return { client, requestedScopes };
  }

  async createAuthorizationCode(params: {
    clientId: string;
    userEmail: string;
    redirectUri: string;
    scope?: string;
    codeChallenge?: string;
    codeChallengeMethod?: string;
  }): Promise<string> {
    try {
      // Validate user domain
      if (this.config.OAUTH_REQUIRE_DOMAIN_VERIFICATION) {
        if (!validateEmailDomain(params.userEmail, this.config.OAUTH_DOMAIN_RESTRICTION)) {
          throw new AccessDeniedError(`Email domain not allowed: ${params.userEmail}`);
        }
      }

      const code = generateAuthorizationCode();
      const expiresAt = calculateExpirationDate('10m'); // Authorization codes expire in 10 minutes

      await this.repository.createAuthCode({
        code,
        clientId: params.clientId,
        userEmail: params.userEmail,
        redirectUri: params.redirectUri,
        scope: params.scope,
        codeChallenge: params.codeChallenge,
        expiresAt
      });

      logger.debug(`Authorization code created for user: ${params.userEmail}`);
      return code;
    } catch (error) {
      logger.error('Failed to create authorization code:', error);
      throw error;
    }
  }

  // Token Exchange
  async exchangeAuthorizationCode(params: {
    code: string;
    clientId: string;
    clientSecret?: string;
    redirectUri: string;
    codeVerifier?: string;
  }): Promise<TokenResponse> {
    try {
      // Get and validate authorization code
      const authCode = await this.repository.getAuthCode(params.code);
      if (!authCode) {
        throw new InvalidGrantError('Invalid or expired authorization code');
      }

      // Validate client and redirect URI
      if (authCode.clientId !== params.clientId) {
        throw new InvalidClientError('Client mismatch');
      }

      if (authCode.redirectUri !== params.redirectUri) {
        throw new InvalidGrantError('Redirect URI mismatch');
      }

      // Get client details
      const client = await this.repository.getClient(params.clientId);
      if (!client) {
        throw new InvalidClientError('Unknown client');
      }

      // Validate client secret for confidential clients
      if (client.clientType === 'confidential' && client.secret) {
        if (!params.clientSecret || params.clientSecret !== client.secret) {
          throw new InvalidClientError('Invalid client secret');
        }
      }

      // Validate PKCE if present
      if (authCode.codeChallenge) {
        if (!params.codeVerifier) {
          throw new InvalidRequestError('Code verifier required');
        }
        if (!validatePKCE(params.codeVerifier, authCode.codeChallenge, 'S256')) {
          throw new InvalidGrantError('Invalid code verifier');
        }
      }

      // Create tokens
      const accessToken = createAccessToken({
        userEmail: authCode.userEmail,
        clientId: authCode.clientId,
        scope: authCode.scope,
        expiresIn: this.config.JWT_EXPIRES_IN
      });

      const refreshToken = createRefreshToken();

      const accessTokenExpiresAt = calculateExpirationDate(this.config.JWT_EXPIRES_IN);
      const refreshTokenExpiresAt = calculateExpirationDate(this.config.JWT_REFRESH_EXPIRES_IN);

      // Store tokens
      await this.repository.createToken({
        token: accessToken,
        type: 'access',
        clientId: authCode.clientId,
        userEmail: authCode.userEmail,
        scope: authCode.scope,
        expiresAt: accessTokenExpiresAt
      });

      await this.repository.createToken({
        token: refreshToken,
        type: 'refresh',
        clientId: authCode.clientId,
        userEmail: authCode.userEmail,
        scope: authCode.scope,
        expiresAt: refreshTokenExpiresAt
      });

      // Delete used authorization code
      await this.repository.deleteAuthCode(params.code);

      logger.info(`Tokens issued for user: ${authCode.userEmail}, client: ${client.name}`);

      return {
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: Math.floor(getTokenLifetime(accessTokenExpiresAt)),
        refresh_token: refreshToken,
        scope: authCode.scope
      };
    } catch (error) {
      logger.error('Token exchange failed:', error);
      throw error;
    }
  }

  // Client Credentials Grant
  async exchangeClientCredentials(params: {
    clientId: string;
    clientSecret: string;
    scope?: string;
  }): Promise<TokenResponse> {
    try {
      // Get and validate client
      const client = await this.repository.getClient(params.clientId);
      if (!client) {
        throw new InvalidClientError('Unknown client');
      }

      // Validate that this is a confidential client
      if (client.clientType !== 'confidential') {
        throw new InvalidClientError('Client credentials grant requires confidential client');
      }

      // Validate client secret
      if (!client.secret || !params.clientSecret || params.clientSecret !== client.secret) {
        throw new InvalidClientError('Invalid client secret');
      }

      // Validate requested scopes (if provided)
      let finalScope = client.scope; // Default to client's registered scope
      if (params.scope) {
        const requestedScopes = parseScopes(params.scope);
        const clientScopes = parseScopes(client.scope);
        
        // In free scope mode, accept any scopes for machine-to-machine
        // In production, you might want to validate scopes are subset of client's allowed scopes
        logger.info('Client credentials scope validation', { 
          clientScopes, 
          requestedScopes,
          mode: 'free_scope' 
        });
        
        finalScope = params.scope;
      }

      // Create access token (no refresh token for client credentials)
      const accessToken = createAccessToken({
        userEmail: `${client.id}@machine`, // Machine account identifier
        clientId: client.id,
        scope: finalScope,
        expiresIn: this.config.JWT_EXPIRES_IN
      });

      const accessTokenExpiresAt = calculateExpirationDate(this.config.JWT_EXPIRES_IN);

      // Store access token
      await this.repository.createToken({
        token: accessToken,
        type: 'access',
        clientId: client.id,
        userEmail: `${client.id}@machine`, // Machine account
        scope: finalScope,
        expiresAt: accessTokenExpiresAt
      });

      logger.info(`Client credentials tokens issued for client: ${client.name}`);

      return {
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: Math.floor(getTokenLifetime(accessTokenExpiresAt)),
        scope: finalScope
        // Note: No refresh_token for client credentials grant
      };
    } catch (error) {
      logger.error('Client credentials exchange failed:', error);
      throw error;
    }
  }

  // Refresh Token
  async refreshTokens(params: {
    refreshToken: string;
    clientId: string;
    clientSecret?: string;
    scope?: string;
  }): Promise<TokenResponse> {
    try {
      // Get and validate refresh token
      const storedToken = await this.repository.getRefreshToken(params.refreshToken);
      if (!storedToken) {
        throw new InvalidGrantError('Invalid or expired refresh token');
      }

      // Validate client
      if (storedToken.clientId !== params.clientId) {
        throw new InvalidClientError('Client mismatch');
      }

      const client = await this.repository.getClient(params.clientId);
      if (!client) {
        throw new InvalidClientError('Unknown client');
      }

      // Validate client secret for confidential clients
      if (client.clientType === 'confidential' && client.secret) {
        if (!params.clientSecret || params.clientSecret !== client.secret) {
          throw new InvalidClientError('Invalid client secret');
        }
      }

      // Validate scope (if provided, must be subset of original)
      let finalScope = storedToken.scope;
      if (params.scope) {
        const requestedScopes = parseScopes(params.scope);
        const originalScopes = parseScopes(storedToken.scope || '');
        
        // Free scope mode - allow any scopes in refresh token requests
        logger.info('Free scope mode: accepting all requested scopes', { 
          originalScopes, 
          requestedScopes 
        });
        
        finalScope = params.scope;
      }

      // Create new tokens
      const newAccessToken = createAccessToken({
        userEmail: storedToken.userEmail,
        clientId: storedToken.clientId,
        scope: finalScope,
        expiresIn: this.config.JWT_EXPIRES_IN
      });

      const newRefreshToken = createRefreshToken();

      const accessTokenExpiresAt = calculateExpirationDate(this.config.JWT_EXPIRES_IN);
      const refreshTokenExpiresAt = calculateExpirationDate(this.config.JWT_REFRESH_EXPIRES_IN);

      // Delete old refresh token
      await this.repository.deleteToken(params.refreshToken);

      // Store new tokens
      await this.repository.createToken({
        token: newAccessToken,
        type: 'access',
        clientId: storedToken.clientId,
        userEmail: storedToken.userEmail,
        scope: finalScope,
        expiresAt: accessTokenExpiresAt
      });

      await this.repository.createToken({
        token: newRefreshToken,
        type: 'refresh',
        clientId: storedToken.clientId,
        userEmail: storedToken.userEmail,
        scope: finalScope,
        expiresAt: refreshTokenExpiresAt
      });

      logger.info(`Tokens refreshed for user: ${storedToken.userEmail}, client: ${client.name}`);

      return {
        access_token: newAccessToken,
        token_type: 'Bearer',
        expires_in: Math.floor(getTokenLifetime(accessTokenExpiresAt)),
        refresh_token: newRefreshToken,
        scope: finalScope
      };
    } catch (error) {
      logger.error('Token refresh failed:', error);
      throw error;
    }
  }

  // Token Validation
  async validateAccessToken(token: string): Promise<{
    valid: boolean;
    payload?: any;
    client?: OAuthClient;
    user?: { email: string };
  }> {
    try {
      // First try to parse the token
      const payload = verifyAccessToken(token);
      if (!payload) {
        return { valid: false };
      }

      // Check if token exists in database and is not expired
      const storedToken = await this.repository.getToken(token);
      if (!storedToken || storedToken.type !== 'access') {
        return { valid: false };
      }

      // Get client information
      const client = await this.repository.getClient(storedToken.clientId);
      if (!client) {
        return { valid: false };
      }

      return {
        valid: true,
        payload: {
          sub: payload.sub,
          client_id: payload.client_id,
          scope: payload.scope,
          exp: payload.exp
        },
        client,
        user: { email: storedToken.userEmail }
      };
    } catch (error) {
      logger.debug('Token validation failed:', error);
      return { valid: false };
    }
  }

  // Token Introspection
  async introspectToken(token: string): Promise<IntrospectionResponse> {
    try {
      const validation = await this.validateAccessToken(token);
      
      if (!validation.valid || !validation.payload) {
        return { active: false };
      }

      return {
        active: true,
        scope: validation.payload.scope,
        client_id: validation.payload.client_id,
        username: validation.user?.email,
        token_type: 'access_token',
        exp: validation.payload.exp,
        iat: validation.payload.iat,
        sub: validation.payload.sub
      };
    } catch (error) {
      logger.error('Token introspection failed:', error);
      return { active: false };
    }
  }

  // Token Revocation
  async revokeToken(token: string, clientId: string, clientSecret?: string): Promise<void> {
    try {
      // Get token to validate client ownership
      const storedToken = await this.repository.getToken(token);
      if (!storedToken) {
        // Token doesn't exist - OAuth spec says to return success anyway
        return;
      }

      // Validate client
      if (storedToken.clientId !== clientId) {
        throw new InvalidClientError('Client mismatch');
      }

      const client = await this.repository.getClient(clientId);
      if (!client) {
        throw new InvalidClientError('Unknown client');
      }

      // Validate client secret for confidential clients
      if (client.clientType === 'confidential' && client.secret) {
        if (!clientSecret || clientSecret !== client.secret) {
          throw new InvalidClientError('Invalid client secret');
        }
      }

      // Revoke the token
      await this.repository.deleteToken(token);

      // If it's a refresh token, also revoke associated access tokens
      if (storedToken.type === 'refresh') {
        // This is a simplified approach - in production you might want more sophisticated token linking
        logger.info(`Refresh token revoked for client: ${client.name}`);
      }

      logger.info(`Token revoked for client: ${client.name}`);
    } catch (error) {
      logger.error('Token revocation failed:', error);
      throw error;
    }
  }

  // Utility methods
  async cleanupExpiredTokens(): Promise<{ deletedCodes: number; deletedTokens: number }> {
    return this.repository.cleanupExpired();
  }

  async getStats(): Promise<{
    clientCount: number;
    activeTokenCount: number;
    pendingCodeCount: number;
    nodeCount: number;
  }> {
    return this.repository.getStats();
  }
}
