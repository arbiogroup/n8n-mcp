import crypto from 'crypto';
import { logger } from '../utils/logger';

export interface OAuthClient {
  client_id: string;
  client_secret?: string;
  redirect_uris: string[];
  client_name?: string;
  client_type: 'public' | 'confidential';
  grant_types: string[];
  token_endpoint_auth_method?: string;
  created_at: number;
}

export interface AuthorizationCode {
  code: string;
  client_id: string;
  redirect_uri: string;
  user_id: string;
  code_challenge?: string;
  code_challenge_method?: string;
  expires_at: number;
  scopes: string[];
  used: boolean;
}

export interface AccessToken {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  refresh_token?: string;
  client_id: string;
  user_id: string;
  scopes: string[];
  created_at: number;
  expires_at: number;
}

export interface RefreshToken {
  refresh_token: string;
  client_id: string;
  user_id: string;
  scopes: string[];
  access_token: string;
  expires_at: number;
  created_at: number;
}

export interface GoogleUserInfo {
  id: string;
  email: string;
  verified_email: boolean;
  name: string;
  given_name: string;
  family_name: string;
  picture: string;
  locale: string;
  hd?: string; // Hosted domain for G Suite
}

export class OAuthService {
  private clients: Map<string, OAuthClient> = new Map();
  private authorizationCodes: Map<string, AuthorizationCode> = new Map();
  private accessTokens: Map<string, AccessToken> = new Map();
  private refreshTokens: Map<string, RefreshToken> = new Map();
  private googleUsers: Map<string, GoogleUserInfo> = new Map();
  
  constructor() {
    // Clean up expired tokens every 5 minutes
    setInterval(() => {
      this.cleanupExpiredTokens();
    }, 5 * 60 * 1000);
  }

  /**
   * Register a new OAuth client (Dynamic Client Registration)
   */
  registerClient(clientInfo: Partial<OAuthClient>): OAuthClient {
    const client_id = this.generateClientId();
    const client_secret = clientInfo.client_type === 'confidential' ? this.generateClientSecret() : undefined;
    
    const client: OAuthClient = {
      client_id,
      client_secret,
      redirect_uris: clientInfo.redirect_uris || [],
      client_name: clientInfo.client_name || 'MCP Client',
      client_type: clientInfo.client_type || 'public',
      grant_types: clientInfo.grant_types || ['authorization_code', 'refresh_token'],
      token_endpoint_auth_method: clientInfo.token_endpoint_auth_method || (clientInfo.client_type === 'confidential' ? 'client_secret_basic' : 'none'),
      created_at: Date.now()
    };
    
    this.clients.set(client_id, client);
    logger.info('OAuth client registered', { client_id, client_type: client.client_type });
    
    return client;
  }

  /**
   * Get client by ID
   */
  getClient(client_id: string): OAuthClient | undefined {
    return this.clients.get(client_id);
  }

  /**
   * Validate redirect URI for a client
   */
  validateRedirectUri(client_id: string, redirect_uri: string): boolean {
    const client = this.getClient(client_id);
    if (!client) return false;
    
    // For localhost URLs, allow any port for development
    if (redirect_uri.startsWith('http://localhost:') || redirect_uri.startsWith('http://127.0.0.1:')) {
      return client.redirect_uris.some(uri => 
        uri.startsWith('http://localhost:') || uri.startsWith('http://127.0.0.1:')
      );
    }
    
    return client.redirect_uris.includes(redirect_uri);
  }

  /**
   * Generate authorization code
   */
  generateAuthorizationCode(
    client_id: string,
    redirect_uri: string,
    user_id: string,
    scopes: string[],
    code_challenge?: string,
    code_challenge_method?: string
  ): string {
    const code = crypto.randomBytes(32).toString('base64url');
    const expires_at = Date.now() + (10 * 60 * 1000); // 10 minutes
    
    const authCode: AuthorizationCode = {
      code,
      client_id,
      redirect_uri,
      user_id,
      code_challenge,
      code_challenge_method,
      expires_at,
      scopes,
      used: false
    };
    
    this.authorizationCodes.set(code, authCode);
    return code;
  }

  /**
   * Exchange authorization code for access token
   */
  exchangeAuthorizationCode(
    code: string,
    client_id: string,
    redirect_uri: string,
    code_verifier?: string
  ): AccessToken | null {
    const authCode = this.authorizationCodes.get(code);
    
    if (!authCode || authCode.used || authCode.expires_at < Date.now()) {
      logger.warn('Invalid or expired authorization code', { code: code.substring(0, 8) + '...' });
      return null;
    }
    
    if (authCode.client_id !== client_id || authCode.redirect_uri !== redirect_uri) {
      logger.warn('Authorization code client_id or redirect_uri mismatch');
      return null;
    }
    
    // Verify PKCE if used
    if (authCode.code_challenge) {
      if (!code_verifier) {
        logger.warn('PKCE: code_verifier required but not provided');
        return null;
      }
      
      if (!this.verifyPKCE(authCode.code_challenge, authCode.code_challenge_method || 'S256', code_verifier)) {
        logger.warn('PKCE verification failed');
        return null;
      }
    }
    
    // Mark code as used
    authCode.used = true;
    
    // Generate access token
    const access_token = crypto.randomBytes(32).toString('base64url');
    const refresh_token = crypto.randomBytes(32).toString('base64url');
    const expires_in = 3600; // 1 hour
    const expires_at = Date.now() + (expires_in * 1000);
    
    const accessToken: AccessToken = {
      access_token,
      token_type: 'Bearer',
      expires_in,
      refresh_token,
      client_id,
      user_id: authCode.user_id,
      scopes: authCode.scopes,
      created_at: Date.now(),
      expires_at
    };
    
    const refreshTokenData: RefreshToken = {
      refresh_token,
      client_id,
      user_id: authCode.user_id,
      scopes: authCode.scopes,
      access_token,
      expires_at: Date.now() + (7 * 24 * 60 * 60 * 1000), // 7 days
      created_at: Date.now()
    };
    
    this.accessTokens.set(access_token, accessToken);
    this.refreshTokens.set(refresh_token, refreshTokenData);
    
    logger.info('Access token generated', { 
      client_id, 
      user_id: authCode.user_id,
      expires_in 
    });
    
    return accessToken;
  }

  /**
   * Validate access token
   */
  validateAccessToken(token: string): AccessToken | null {
    const accessToken = this.accessTokens.get(token);
    
    if (!accessToken || accessToken.expires_at < Date.now()) {
      return null;
    }
    
    return accessToken;
  }

  /**
   * Refresh access token
   */
  refreshAccessToken(refresh_token: string, client_id: string): AccessToken | null {
    const refreshTokenData = this.refreshTokens.get(refresh_token);
    
    if (!refreshTokenData || refreshTokenData.expires_at < Date.now() || refreshTokenData.client_id !== client_id) {
      return null;
    }
    
    // Revoke old access token
    this.accessTokens.delete(refreshTokenData.access_token);
    
    // Generate new access token
    const new_access_token = crypto.randomBytes(32).toString('base64url');
    const expires_in = 3600; // 1 hour
    const expires_at = Date.now() + (expires_in * 1000);
    
    const accessToken: AccessToken = {
      access_token: new_access_token,
      token_type: 'Bearer',
      expires_in,
      refresh_token,
      client_id,
      user_id: refreshTokenData.user_id,
      scopes: refreshTokenData.scopes,
      created_at: Date.now(),
      expires_at
    };
    
    // Update refresh token with new access token
    refreshTokenData.access_token = new_access_token;
    
    this.accessTokens.set(new_access_token, accessToken);
    
    logger.info('Access token refreshed', { client_id, user_id: refreshTokenData.user_id });
    
    return accessToken;
  }

  /**
   * Store Google user info
   */
  storeGoogleUser(user: GoogleUserInfo): string {
    const user_id = `google:${user.id}`;
    this.googleUsers.set(user_id, user);
    return user_id;
  }

  /**
   * Get Google user info
   */
  getGoogleUser(user_id: string): GoogleUserInfo | undefined {
    return this.googleUsers.get(user_id);
  }

  /**
   * Verify PKCE code challenge
   */
  private verifyPKCE(code_challenge: string, method: string, code_verifier: string): boolean {
    if (method === 'plain') {
      return code_challenge === code_verifier;
    } else if (method === 'S256') {
      const hash = crypto.createHash('sha256').update(code_verifier).digest('base64url');
      return code_challenge === hash;
    }
    return false;
  }

  /**
   * Generate client ID
   */
  private generateClientId(): string {
    return crypto.randomBytes(16).toString('hex');
  }

  /**
   * Generate client secret
   */
  private generateClientSecret(): string {
    return crypto.randomBytes(32).toString('base64url');
  }

  /**
   * Clean up expired tokens
   */
  private cleanupExpiredTokens(): void {
    const now = Date.now();
    let cleaned = 0;
    
    // Clean up authorization codes
    for (const [code, authCode] of this.authorizationCodes.entries()) {
      if (authCode.expires_at < now) {
        this.authorizationCodes.delete(code);
        cleaned++;
      }
    }
    
    // Clean up access tokens
    for (const [token, accessToken] of this.accessTokens.entries()) {
      if (accessToken.expires_at < now) {
        this.accessTokens.delete(token);
        cleaned++;
      }
    }
    
    // Clean up refresh tokens
    for (const [token, refreshToken] of this.refreshTokens.entries()) {
      if (refreshToken.expires_at < now) {
        this.refreshTokens.delete(token);
        cleaned++;
      }
    }
    
    if (cleaned > 0) {
      logger.debug(`Cleaned up ${cleaned} expired tokens`);
    }
  }

  /**
   * Get statistics
   */
  getStats() {
    return {
      clients: this.clients.size,
      authorizationCodes: this.authorizationCodes.size,
      accessTokens: this.accessTokens.size,
      refreshTokens: this.refreshTokens.size,
      googleUsers: this.googleUsers.size
    };
  }
}

// Singleton instance
export const oauthService = new OAuthService();
