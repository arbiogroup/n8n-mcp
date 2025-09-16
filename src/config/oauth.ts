import dotenv from 'dotenv';

// OAuth 2.1 configuration interface
export interface OAuthConfig {
  OAUTH_ISSUER: string;
  OAUTH_AUTHORIZATION_ENDPOINT: string;
  OAUTH_TOKEN_ENDPOINT: string;
  OAUTH_REVOCATION_ENDPOINT: string;
  OAUTH_INTROSPECTION_ENDPOINT: string;
  OAUTH_JWKS_URI: string;
  
  // Google OAuth (existing)
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  GOOGLE_CALLBACK_URL: string;
  
  // JWT configuration (existing)
  JWT_SECRET: string;
  JWT_EXPIRES_IN: string;
  JWT_REFRESH_EXPIRES_IN: string;
  
  // OAuth specific settings
  OAUTH_DOMAIN_RESTRICTION: string;
  OAUTH_REQUIRE_DOMAIN_VERIFICATION: boolean;
  OAUTH_ALLOW_DYNAMIC_REGISTRATION: boolean;
  OAUTH_CODE_CHALLENGE_METHODS: string;
}

let cachedConfig: OAuthConfig | null = null;

export function getOAuthConfig(): OAuthConfig {
  if (!cachedConfig) {
    dotenv.config();
    
    // Parse environment variables with defaults
    cachedConfig = {
      OAUTH_ISSUER: process.env.OAUTH_ISSUER || 'https://flow.arbio.io',
      OAUTH_AUTHORIZATION_ENDPOINT: process.env.OAUTH_AUTHORIZATION_ENDPOINT || '/oauth/authorize',
      OAUTH_TOKEN_ENDPOINT: process.env.OAUTH_TOKEN_ENDPOINT || '/oauth/token',
      OAUTH_REVOCATION_ENDPOINT: process.env.OAUTH_REVOCATION_ENDPOINT || '/oauth/revoke',
      OAUTH_INTROSPECTION_ENDPOINT: process.env.OAUTH_INTROSPECTION_ENDPOINT || '/oauth/introspect',
      OAUTH_JWKS_URI: process.env.OAUTH_JWKS_URI || '/.well-known/jwks.json',
      
      // Google OAuth (existing - these should be available from your AWS config)
      GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID || '',
      GOOGLE_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET || '',
      GOOGLE_CALLBACK_URL: process.env.GOOGLE_CALLBACK_URL || process.env.OAUTH_REDIRECT_URI || '',
      
      // JWT configuration (existing)
      JWT_SECRET: process.env.JWT_SECRET || '',
      JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || '1h',
      JWT_REFRESH_EXPIRES_IN: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
      
      // OAuth specific settings
      OAUTH_DOMAIN_RESTRICTION: process.env.OAUTH_DOMAIN_RESTRICTION || 'arbio-group.com',
      OAUTH_REQUIRE_DOMAIN_VERIFICATION: process.env.OAUTH_REQUIRE_DOMAIN_VERIFICATION === 'true',
      OAUTH_ALLOW_DYNAMIC_REGISTRATION: process.env.OAUTH_ALLOW_DYNAMIC_REGISTRATION !== 'false', // Default to true
      OAUTH_CODE_CHALLENGE_METHODS: process.env.OAUTH_CODE_CHALLENGE_METHODS || 'S256',
    };
    
    // Basic validation
    if (!cachedConfig.GOOGLE_CLIENT_ID || !cachedConfig.GOOGLE_CLIENT_SECRET) {
      console.warn('Warning: Google OAuth credentials not configured');
    }
    
    if (!cachedConfig.JWT_SECRET || cachedConfig.JWT_SECRET.length < 32) {
      console.warn('Warning: JWT_SECRET should be at least 32 characters');
    }
  }
  
  return cachedConfig!; // Non-null assertion since we just set it above
}

export const OAUTH_SCOPES = {
  MCP_READ: 'mcp:read',
  MCP_WRITE: 'mcp:write',
  WORKFLOWS_READ: 'workflows:read',
  WORKFLOWS_WRITE: 'workflows:write',
  USER_PROFILE: 'user:profile',
  ADMIN: 'admin',
} as const;

export const GRANT_TYPES = {
  AUTHORIZATION_CODE: 'authorization_code',
  REFRESH_TOKEN: 'refresh_token',
} as const;

export const RESPONSE_TYPES = {
  CODE: 'code',
} as const;

export const CLIENT_TYPES = {
  PUBLIC: 'public',
  CONFIDENTIAL: 'confidential',
} as const;

// Helper functions
export function getSupportedScopes(): string[] {
  // Free scope mode - return wildcard to indicate all scopes are supported
  return ['*'];
}

export function isValidScope(scope: string): boolean {
  // Free scope mode - all scopes are valid
  return true;
}

export function validateScopes(requestedScopes: string[]): boolean {
  // Free scope mode - all scopes are always valid
  return true;
}

export function parseScopes(scopeString: string): string[] {
  if (!scopeString) return [];
  return scopeString.split(' ').filter(s => s.length > 0);
}

export function formatScopes(scopes: string[]): string {
  return scopes.join(' ');
}
