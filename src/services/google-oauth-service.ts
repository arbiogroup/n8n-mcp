import crypto from 'crypto';
import { logger } from '../utils/logger';
import { GoogleUserInfo } from './oauth-service';

export interface GoogleOAuthConfig {
  clientId: string;
  clientSecret: string;
  callbackUrl: string;
  domainRestriction?: string;
  requireDomainVerification?: boolean;
}

export interface GoogleAuthState {
  state: string;
  original_client_id: string;
  original_redirect_uri: string;
  code_challenge?: string;
  code_challenge_method?: string;
  scopes: string[];
  expires_at: number;
  original_state?: string;
}

export class GoogleOAuthService {
  private config: GoogleOAuthConfig;
  private authStates: Map<string, GoogleAuthState> = new Map();
  
  constructor() {
    this.config = {
      clientId: process.env.GOOGLE_CLIENT_ID || '',
      clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
      callbackUrl: process.env.GOOGLE_CALLBACK_URL || process.env.OAUTH_REDIRECT_URI || '',
      domainRestriction: process.env.OAUTH_DOMAIN_RESTRICTION,
      requireDomainVerification: process.env.OAUTH_REQUIRE_DOMAIN_VERIFICATION === 'true'
    };
    
    // Clean up expired states every 5 minutes
    setInterval(() => {
      this.cleanupExpiredStates();
    }, 5 * 60 * 1000);
  }

  /**
   * Check if Google OAuth is configured
   */
  isConfigured(): boolean {
    return !!(this.config.clientId && this.config.clientSecret && this.config.callbackUrl);
  }

  /**
   * Get Google OAuth configuration for error messages
   */
  getConfigStatus(): { configured: boolean; missing: string[] } {
    const missing: string[] = [];
    if (!this.config.clientId) missing.push('GOOGLE_CLIENT_ID');
    if (!this.config.clientSecret) missing.push('GOOGLE_CLIENT_SECRET');
    if (!this.config.callbackUrl) missing.push('GOOGLE_CALLBACK_URL or OAUTH_REDIRECT_URI');
    
    return {
      configured: missing.length === 0,
      missing
    };
  }

  /**
   * Generate Google OAuth authorization URL
   */
  generateAuthUrl(
    originalClientId: string,
    originalRedirectUri: string,
    codeChallenge?: string,
    codeChallengeMethod?: string,
    scopes: string[] = ['openid', 'email', 'profile'],
    originalState?: string
  ): string {
    const state = crypto.randomBytes(32).toString('base64url');
    
    // Store the original OAuth flow parameters
    const authState: GoogleAuthState = {
      state,
      original_client_id: originalClientId,
      original_redirect_uri: originalRedirectUri,
      code_challenge: codeChallenge,
      code_challenge_method: codeChallengeMethod,
      scopes,
      expires_at: Date.now() + (10 * 60 * 1000), // 10 minutes
      original_state: originalState
    };
    
    this.authStates.set(state, authState);
    
    const params = new URLSearchParams({
      client_id: this.config.clientId,
      redirect_uri: this.config.callbackUrl,
      response_type: 'code',
      scope: 'openid email profile',
      state,
      access_type: 'offline',
      prompt: 'consent'
    });
    
    // Add domain hint if domain restriction is configured
    if (this.config.domainRestriction) {
      params.set('hd', this.config.domainRestriction);
    }
    
    const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
    
    logger.info('Generated Google OAuth URL', { 
      state: state.substring(0, 8) + '...',
      originalClientId,
      domainRestriction: this.config.domainRestriction 
    });
    
    return authUrl;
  }

  /**
   * Handle Google OAuth callback
   */
  async handleCallback(code: string, state: string): Promise<{ authState: GoogleAuthState; userInfo: GoogleUserInfo } | null> {
    const authState = this.authStates.get(state);
    
    if (!authState || authState.expires_at < Date.now()) {
      logger.warn('Invalid or expired Google OAuth state', { state: state.substring(0, 8) + '...' });
      return null;
    }
    
    try {
      // Exchange code for tokens
      const tokenResponse = await this.exchangeCodeForToken(code);
      if (!tokenResponse) {
        logger.error('Failed to exchange Google OAuth code for token');
        return null;
      }
      
      // Get user info
      const userInfo = await this.getUserInfo(tokenResponse.access_token);
      if (!userInfo) {
        logger.error('Failed to get Google user info');
        return null;
      }
      
      // Validate domain if required
      if (!this.validateUserDomain(userInfo)) {
        logger.warn('User domain validation failed', { 
          email: userInfo.email,
          domain: userInfo.hd,
          requiredDomain: this.config.domainRestriction 
        });
        return null;
      }
      
      // Clean up state
      this.authStates.delete(state);
      
      logger.info('Google OAuth callback successful', { 
        email: userInfo.email,
        domain: userInfo.hd 
      });
      
      return { authState, userInfo };
      
    } catch (error) {
      logger.error('Google OAuth callback error', error);
      return null;
    }
  }

  /**
   * Exchange authorization code for access token
   */
  private async exchangeCodeForToken(code: string): Promise<{ access_token: string; refresh_token?: string } | null> {
    try {
      const response = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          client_id: this.config.clientId,
          client_secret: this.config.clientSecret,
          code,
          grant_type: 'authorization_code',
          redirect_uri: this.config.callbackUrl,
        }),
      });
      
      if (!response.ok) {
        const errorText = await response.text();
        logger.error('Google token exchange failed', { 
          status: response.status,
          statusText: response.statusText,
          error: errorText 
        });
        return null;
      }
      
      const tokenData = await response.json() as any;
      return {
        access_token: tokenData.access_token,
        refresh_token: tokenData.refresh_token
      };
      
    } catch (error) {
      logger.error('Google token exchange error', error);
      return null;
    }
  }

  /**
   * Get user info from Google
   */
  private async getUserInfo(accessToken: string): Promise<GoogleUserInfo | null> {
    try {
      const response = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });
      
      if (!response.ok) {
        logger.error('Google userinfo request failed', { 
          status: response.status,
          statusText: response.statusText 
        });
        return null;
      }
      
      const userInfo = await response.json();
      return userInfo as GoogleUserInfo;
      
    } catch (error) {
      logger.error('Google userinfo error', error);
      return null;
    }
  }

  /**
   * Validate user domain
   */
  private validateUserDomain(userInfo: GoogleUserInfo): boolean {
    // If no domain restriction, allow all verified emails
    if (!this.config.domainRestriction) {
      return userInfo.verified_email;
    }
    
    // If domain verification is required, check the hosted domain
    if (this.config.requireDomainVerification) {
      return userInfo.hd === this.config.domainRestriction;
    }
    
    // Otherwise, check if email ends with the required domain
    return userInfo.verified_email && userInfo.email.endsWith(`@${this.config.domainRestriction}`);
  }

  /**
   * Clean up expired auth states
   */
  private cleanupExpiredStates(): void {
    const now = Date.now();
    let cleaned = 0;
    
    for (const [state, authState] of this.authStates.entries()) {
      if (authState.expires_at < now) {
        this.authStates.delete(state);
        cleaned++;
      }
    }
    
    if (cleaned > 0) {
      logger.debug(`Cleaned up ${cleaned} expired Google OAuth states`);
    }
  }

  /**
   * Get statistics
   */
  getStats() {
    return {
      configured: this.isConfigured(),
      activeStates: this.authStates.size,
      config: {
        hasClientId: !!this.config.clientId,
        hasClientSecret: !!this.config.clientSecret,
        hasCallbackUrl: !!this.config.callbackUrl,
        domainRestriction: this.config.domainRestriction,
        requireDomainVerification: this.config.requireDomainVerification
      }
    };
  }
}

// Singleton instance
export const googleOAuthService = new GoogleOAuthService();
