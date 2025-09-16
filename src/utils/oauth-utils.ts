import crypto from 'crypto';
// import jwt from 'jsonwebtoken'; // TODO: Fix dependency issue
import { getOAuthConfig } from '../config/oauth';
import { AccessTokenPayload } from '../models/oauth-models';

/**
 * Generate a secure random token
 */
export function generateSecureToken(length: number = 32): string {
  return crypto.randomBytes(length).toString('base64url');
}

/**
 * Generate OAuth client ID
 */
export function generateClientId(): string {
  return `client_${crypto.randomBytes(16).toString('hex')}`;
}

/**
 * Generate OAuth client secret
 */
export function generateClientSecret(): string {
  return crypto.randomBytes(32).toString('base64url');
}

/**
 * Generate authorization code
 */
export function generateAuthorizationCode(): string {
  return crypto.randomBytes(32).toString('base64url');
}

/**
 * Create PKCE code challenge from verifier
 */
export function createCodeChallenge(verifier: string): string {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

/**
 * Validate PKCE code verifier against challenge
 */
export function validatePKCE(verifier: string, challenge: string, method: string = 'S256'): boolean {
  if (method !== 'S256') {
    throw new Error('Only S256 PKCE method is supported');
  }
  const computedChallenge = createCodeChallenge(verifier);
  return computedChallenge === challenge;
}

/**
 * Create simple access token (opaque for now, JWT later)
 */
export function createAccessToken(payload: {
  userEmail: string;
  clientId: string;
  scope?: string;
  expiresIn?: string;
}): string {
  // For now, create an opaque token - we'll implement JWT later
  // Format: base64(userEmail:clientId:scope:timestamp:random)
  const timestamp = Date.now();
  const random = crypto.randomBytes(8).toString('hex');
  const tokenData = `${payload.userEmail}:${payload.clientId}:${payload.scope || ''}:${timestamp}:${random}`;
  return Buffer.from(tokenData).toString('base64url');
}

/**
 * Verify simple access token (parse opaque token for now)
 */
export function verifyAccessToken(token: string): AccessTokenPayload | null {
  try {
    const decoded = Buffer.from(token, 'base64url').toString('utf-8');
    const parts = decoded.split(':');
    
    if (parts.length !== 5) return null;
    
    const [userEmail, clientId, scope, timestamp, random] = parts;
    const tokenTime = parseInt(timestamp, 10);
    
    // Simple validation - token should not be older than configured expiry
    const config = getOAuthConfig();
    const maxAge = parseExpiresIn(config.JWT_EXPIRES_IN) * 1000; // Convert to ms
    
    if (Date.now() - tokenTime > maxAge) {
      return null; // Token expired
    }
    
    return {
      sub: userEmail,
      client_id: clientId,
      scope: scope || undefined,
      iat: Math.floor(tokenTime / 1000),
      exp: Math.floor((tokenTime + maxAge) / 1000),
      iss: config.OAUTH_ISSUER,
      aud: config.OAUTH_ISSUER
    };
  } catch (error) {
    return null;
  }
}

/**
 * Create refresh token (opaque)
 */
export function createRefreshToken(): string {
  return crypto.randomBytes(32).toString('base64url');
}

/**
 * Parse expires_in string to seconds
 */
export function parseExpiresIn(expiresIn: string): number {
  const match = expiresIn.match(/^(\d+)([smhd]?)$/);
  if (!match) {
    throw new Error(`Invalid expires_in format: ${expiresIn}`);
  }
  
  const value = parseInt(match[1], 10);
  const unit = match[2] || 's';
  
  switch (unit) {
    case 's': return value;
    case 'm': return value * 60;
    case 'h': return value * 60 * 60;
    case 'd': return value * 60 * 60 * 24;
    default: throw new Error(`Invalid time unit: ${unit}`);
  }
}

/**
 * Calculate expiration date from expires_in
 */
export function calculateExpirationDate(expiresIn: string): string {
  const seconds = parseExpiresIn(expiresIn);
  const expirationDate = new Date(Date.now() + seconds * 1000);
  return expirationDate.toISOString();
}

/**
 * Validate redirect URI
 */
export function validateRedirectUri(clientRedirectUris: string[], providedUri: string): boolean {
  return clientRedirectUris.includes(providedUri);
}

/**
 * Parse scope string into array
 */
export function parseScope(scope: string): string[] {
  return scope ? scope.split(' ').filter(s => s.length > 0) : [];
}

/**
 * Format scope array into string
 */
export function formatScope(scopes: string[]): string {
  return scopes.join(' ');
}

/**
 * Validate scope against allowed scopes
 */
export function validateScope(requestedScopes: string[], allowedScopes: string[]): boolean {
  return requestedScopes.every(scope => allowedScopes.includes(scope));
}

/**
 * Check if email domain is allowed
 */
export function validateEmailDomain(email: string, allowedDomain?: string): boolean {
  if (!allowedDomain) return true;
  
  const emailDomain = email.split('@')[1];
  return emailDomain === allowedDomain;
}

/**
 * Generate state parameter for OAuth flows
 */
export function generateState(): string {
  return crypto.randomBytes(16).toString('base64url');
}

/**
 * Create error query parameters for redirect
 */
export function createErrorParams(error: string, errorDescription?: string, state?: string): URLSearchParams {
  const params = new URLSearchParams();
  params.set('error', error);
  
  if (errorDescription) {
    params.set('error_description', errorDescription);
  }
  
  if (state) {
    params.set('state', state);
  }
  
  return params;
}

/**
 * Create success query parameters for redirect
 */
export function createSuccessParams(code: string, state?: string): URLSearchParams {
  const params = new URLSearchParams();
  params.set('code', code);
  
  if (state) {
    params.set('state', state);
  }
  
  return params;
}

/**
 * Hash client secret for storage (basic protection)
 */
export function hashClientSecret(secret: string): string {
  return crypto.createHash('sha256').update(secret).digest('hex');
}

/**
 * Verify client secret against hash
 */
export function verifyClientSecret(secret: string, hash: string): boolean {
  const secretHash = hashClientSecret(secret);
  return crypto.timingSafeEqual(Buffer.from(secretHash), Buffer.from(hash));
}

/**
 * Generate PKCE code verifier
 */
export function generateCodeVerifier(): string {
  return crypto.randomBytes(32).toString('base64url');
}

/**
 * Check if token is expired
 */
export function isTokenExpired(expiresAt: string): boolean {
  return new Date(expiresAt) < new Date();
}

/**
 * Get remaining token lifetime in seconds
 */
export function getTokenLifetime(expiresAt: string): number {
  const now = Date.now();
  const expires = new Date(expiresAt).getTime();
  const remaining = Math.max(0, Math.floor((expires - now) / 1000));
  return remaining;
}
