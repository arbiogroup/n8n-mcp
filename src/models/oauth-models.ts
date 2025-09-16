// OAuth 2.1 Models and Types for n8n-MCP

export interface OAuthClient {
  id: string;
  name: string;
  secret?: string; // Optional for public clients
  redirectUris: string[];
  scope: string;
  clientType?: 'public' | 'confidential';
  createdAt: string;
}

export interface OAuthUser {
  email: string; // Using email as primary identifier (from Google)
  name?: string;
  picture?: string;
  domain?: string;
  verified?: boolean;
  googleId?: string;
}

export interface OAuthAuthorizationCode {
  code: string;
  clientId: string;
  userEmail: string;
  redirectUri: string;
  scope?: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  expiresAt: string;
  createdAt: string;
}

export interface OAuthToken {
  token: string;
  type: 'access' | 'refresh';
  clientId: string;
  userEmail: string;
  scope?: string;
  expiresAt: string;
  createdAt: string;
}

// Request/Response types for OAuth endpoints

export interface AuthorizeRequest {
  response_type: string;
  client_id: string;
  redirect_uri: string;
  scope?: string;
  state?: string;
  code_challenge?: string;
  code_challenge_method?: string;
}

export interface TokenRequest {
  grant_type: string;
  code?: string; // For authorization_code grant
  redirect_uri?: string;
  client_id: string;
  client_secret?: string;
  code_verifier?: string; // For PKCE
  refresh_token?: string; // For refresh_token grant
  scope?: string; // For refresh_token grant scope restriction
}

export interface TokenResponse {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  refresh_token?: string;
  scope?: string;
}

export interface ErrorResponse {
  error: string;
  error_description?: string;
  error_uri?: string;
  state?: string;
}

export interface ClientRegistrationRequest {
  client_name: string;
  redirect_uris: string[];
  grant_types?: string[];
  scope?: string;
  client_type?: 'public' | 'confidential';
}

export interface ClientRegistrationResponse {
  client_id: string;
  client_secret?: string;
  client_name: string;
  redirect_uris: string[];
  grant_types: string[];
  scope: string;
  client_type: 'public' | 'confidential';
}

export interface IntrospectionRequest {
  token: string;
  token_type_hint?: 'access_token' | 'refresh_token';
}

export interface IntrospectionResponse {
  active: boolean;
  scope?: string;
  client_id?: string;
  username?: string;
  token_type?: string;
  exp?: number;
  iat?: number;
  sub?: string;
}

export interface RevocationRequest {
  token: string;
  token_type_hint?: 'access_token' | 'refresh_token';
}

// JWT Payload for access tokens
export interface AccessTokenPayload {
  sub: string; // user email
  client_id: string;
  scope?: string;
  iat: number;
  exp: number;
  iss: string;
  aud: string;
}

// Utility types for validation
export interface PKCEParams {
  codeChallenge: string;
  codeChallengeMethod: 'S256';
  codeVerifier: string;
}

export interface GoogleUserInfo {
  id: string;
  email: string;
  verified_email: boolean;
  name?: string;
  picture?: string;
  given_name?: string;
  family_name?: string;
  locale?: string;
}

// Database row types (matching your SQLite schema)
export interface OAuthClientRow {
  id: string;
  name: string;
  secret: string | null;
  redirect_uris: string; // JSON string
  scope: string;
  created_at: string;
}

export interface OAuthTokenRow {
  token: string;
  type: 'access' | 'refresh';
  client_id: string;
  user_email: string;
  scope: string | null;
  expires_at: string;
  created_at: string;
}

export interface OAuthCodeRow {
  code: string;
  client_id: string;
  user_email: string;
  redirect_uri: string;
  scope: string | null;
  code_challenge: string | null;
  expires_at: string;
  created_at: string;
}

// Error types
export class OAuthError extends Error {
  constructor(
    public error: string,
    public errorDescription?: string,
    public statusCode: number = 400
  ) {
    super(`${error}: ${errorDescription || 'OAuth error'}`);
    this.name = 'OAuthError';
  }
}

export class InvalidClientError extends OAuthError {
  constructor(message?: string) {
    super('invalid_client', message || 'Client authentication failed', 401);
  }
}

export class InvalidGrantError extends OAuthError {
  constructor(message?: string) {
    super('invalid_grant', message || 'The provided authorization grant is invalid', 400);
  }
}

export class InvalidRequestError extends OAuthError {
  constructor(message?: string) {
    super('invalid_request', message || 'The request is missing a required parameter', 400);
  }
}

export class InvalidScopeError extends OAuthError {
  constructor(message?: string) {
    super('invalid_scope', message || 'The requested scope is invalid', 400);
  }
}

export class UnsupportedGrantTypeError extends OAuthError {
  constructor(message?: string) {
    super('unsupported_grant_type', message || 'The authorization grant type is not supported', 400);
  }
}

export class AccessDeniedError extends OAuthError {
  constructor(message?: string) {
    super('access_denied', message || 'The resource owner denied the request', 403);
  }
}
