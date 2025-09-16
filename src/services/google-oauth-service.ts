import { getOAuthConfig } from '../config/oauth';
import { GoogleUserInfo } from '../models/oauth-models';
import { validateEmailDomain, generateState } from '../utils/oauth-utils';
import { logger } from '../utils/logger';

/**
 * Google OAuth 2.0 integration service for user authentication
 * Handles the flow: User -> Google OAuth -> Your Authorization Server
 */
export class GoogleOAuthService {
  private config = getOAuthConfig();

  constructor() {
    // Validate Google OAuth configuration
    if (!this.config.GOOGLE_CLIENT_ID || !this.config.GOOGLE_CLIENT_SECRET) {
      logger.warn('Google OAuth credentials not configured properly');
    }
  }

  /**
   * Generate Google OAuth authorization URL
   */
  generateAuthUrl(state?: string, additionalScopes?: string[]): string {
    const authState = state || generateState();
    
    const scopes = [
      'openid',
      'email',
      'profile',
      ...(additionalScopes || [])
    ];

    const params = new URLSearchParams({
      client_id: this.config.GOOGLE_CLIENT_ID,
      redirect_uri: this.config.GOOGLE_CALLBACK_URL,
      response_type: 'code',
      scope: scopes.join(' '),
      state: authState,
      access_type: 'offline', // To get refresh token
      prompt: 'consent' // Force consent to ensure refresh token
    });

    const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
    
    logger.debug(`Generated Google auth URL for state: ${authState}`);
    return authUrl;
  }

  /**
   * Exchange Google authorization code for tokens
   */
  async exchangeCodeForTokens(code: string): Promise<{
    access_token: string;
    refresh_token?: string;
    expires_in: number;
    token_type: string;
  }> {
    try {
      const tokenUrl = 'https://oauth2.googleapis.com/token';
      
      const params = new URLSearchParams({
        client_id: this.config.GOOGLE_CLIENT_ID,
        client_secret: this.config.GOOGLE_CLIENT_SECRET,
        code,
        grant_type: 'authorization_code',
        redirect_uri: this.config.GOOGLE_CALLBACK_URL
      });

      const response = await fetch(tokenUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: params.toString()
      });

      if (!response.ok) {
        const errorData = await response.text();
        throw new Error(`Google token exchange failed: ${response.status} ${errorData}`);
      }

      const tokens = await response.json() as {
        access_token: string;
        refresh_token?: string;
        expires_in: number;
        token_type: string;
      };
      
      logger.debug('Successfully exchanged Google authorization code for tokens');
      return tokens;
    } catch (error) {
      logger.error('Google token exchange failed:', error);
      throw new Error('Failed to exchange authorization code with Google');
    }
  }

  /**
   * Get user info from Google using access token
   */
  async getUserInfo(accessToken: string): Promise<GoogleUserInfo> {
    try {
      const userInfoUrl = 'https://www.googleapis.com/oauth2/v2/userinfo';
      
      const response = await fetch(userInfoUrl, {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Accept': 'application/json'
        }
      });

      if (!response.ok) {
        const errorData = await response.text();
        throw new Error(`Google userinfo request failed: ${response.status} ${errorData}`);
      }

      const userInfo = await response.json() as GoogleUserInfo;
      
      logger.debug(`Retrieved user info for Google user: ${userInfo.email}`);
      return userInfo;
    } catch (error) {
      logger.error('Google userinfo request failed:', error);
      throw new Error('Failed to get user info from Google');
    }
  }

  /**
   * Validate user against domain restrictions
   */
  validateUser(userInfo: GoogleUserInfo): {
    valid: boolean;
    reason?: string;
    user?: {
      email: string;
      name?: string;
      picture?: string;
      verified: boolean;
      domain: string;
    };
  } {
    try {
      // Check if email is verified
      if (!userInfo.verified_email) {
        return {
          valid: false,
          reason: 'Email not verified with Google'
        };
      }

      // Check domain restriction
      if (this.config.OAUTH_REQUIRE_DOMAIN_VERIFICATION) {
        if (!validateEmailDomain(userInfo.email, this.config.OAUTH_DOMAIN_RESTRICTION)) {
          return {
            valid: false,
            reason: `Email domain not allowed. Required domain: ${this.config.OAUTH_DOMAIN_RESTRICTION}`
          };
        }
      }

      // Extract domain from email
      const domain = userInfo.email.split('@')[1];

      const validatedUser = {
        email: userInfo.email,
        name: userInfo.name,
        picture: userInfo.picture,
        verified: userInfo.verified_email,
        domain
      };

      logger.info(`User validated: ${userInfo.email} (domain: ${domain})`);

      return {
        valid: true,
        user: validatedUser
      };
    } catch (error) {
      logger.error('User validation failed:', error);
      return {
        valid: false,
        reason: 'User validation error'
      };
    }
  }

  /**
   * Complete Google OAuth flow - exchange code and validate user
   */
  async completeOAuthFlow(code: string): Promise<{
    success: boolean;
    user?: {
      email: string;
      name?: string;
      picture?: string;
      verified: boolean;
      domain: string;
      googleId: string;
    };
    tokens?: {
      access_token: string;
      refresh_token?: string;
      expires_in: number;
    };
    error?: string;
  }> {
    try {
      // Step 1: Exchange code for tokens
      const tokens = await this.exchangeCodeForTokens(code);

      // Step 2: Get user info
      const userInfo = await this.getUserInfo(tokens.access_token);

      // Step 3: Validate user
      const validation = this.validateUser(userInfo);

      if (!validation.valid) {
        return {
          success: false,
          error: validation.reason || 'User validation failed'
        };
      }

      // Step 4: Return validated user with Google ID
      return {
        success: true,
        user: {
          ...validation.user!,
          googleId: userInfo.id
        },
        tokens: {
          access_token: tokens.access_token,
          refresh_token: tokens.refresh_token,
          expires_in: tokens.expires_in
        }
      };
    } catch (error) {
      logger.error('Google OAuth flow failed:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Google OAuth flow failed'
      };
    }
  }

  /**
   * Refresh Google access token using refresh token
   */
  async refreshAccessToken(refreshToken: string): Promise<{
    access_token: string;
    expires_in: number;
    token_type: string;
  }> {
    try {
      const tokenUrl = 'https://oauth2.googleapis.com/token';
      
      const params = new URLSearchParams({
        client_id: this.config.GOOGLE_CLIENT_ID,
        client_secret: this.config.GOOGLE_CLIENT_SECRET,
        refresh_token: refreshToken,
        grant_type: 'refresh_token'
      });

      const response = await fetch(tokenUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: params.toString()
      });

      if (!response.ok) {
        const errorData = await response.text();
        throw new Error(`Google token refresh failed: ${response.status} ${errorData}`);
      }

      const tokens = await response.json() as {
        access_token: string;
        expires_in: number;
        token_type: string;
      };
      
      logger.debug('Successfully refreshed Google access token');
      return tokens;
    } catch (error) {
      logger.error('Google token refresh failed:', error);
      throw new Error('Failed to refresh Google access token');
    }
  }

  /**
   * Revoke Google tokens
   */
  async revokeToken(token: string): Promise<boolean> {
    try {
      const revokeUrl = `https://oauth2.googleapis.com/revoke?token=${encodeURIComponent(token)}`;
      
      const response = await fetch(revokeUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        }
      });

      const success = response.ok;
      
      if (success) {
        logger.debug('Successfully revoked Google token');
      } else {
        logger.warn('Failed to revoke Google token:', response.status);
      }
      
      return success;
    } catch (error) {
      logger.error('Google token revocation failed:', error);
      return false;
    }
  }

  /**
   * Get configuration info for debugging
   */
  getConfigInfo(): {
    hasClientId: boolean;
    hasClientSecret: boolean;
    callbackUrl: string;
    domainRestriction: string;
    requireDomainVerification: boolean;
  } {
    return {
      hasClientId: !!this.config.GOOGLE_CLIENT_ID,
      hasClientSecret: !!this.config.GOOGLE_CLIENT_SECRET,
      callbackUrl: this.config.GOOGLE_CALLBACK_URL,
      domainRestriction: this.config.OAUTH_DOMAIN_RESTRICTION,
      requireDomainVerification: this.config.OAUTH_REQUIRE_DOMAIN_VERIFICATION
    };
  }
}
