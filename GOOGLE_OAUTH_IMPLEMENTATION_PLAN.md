# Google OAuth 2.0 Implementation Plan for n8n-MCP Server

## Overview

This plan details the step-by-step implementation of Google OAuth 2.0 authentication to replace the existing AUTH_TOKEN system, enabling secure integration with Claude AI and ChatGPT for Google Workspace organizations.

## Prerequisites

- Google Cloud Console project with OAuth 2.0 credentials
- Google Workspace domain (for organization-wide access)
- Node.js 18+ environment
- Existing n8n-MCP server codebase

## Phase 1: Dependencies and Configuration

### Step 1.1: Install OAuth Dependencies

```bash
npm install passport passport-google-oauth20 express-session jsonwebtoken
npm install --save-dev @types/passport @types/passport-google-oauth20 @types/express-session @types/jsonwebtoken
```

### Step 1.2: Environment Variables Setup

Create new environment variables in `.env`:

```env
# Google OAuth Configuration
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GOOGLE_CALLBACK_URL=http://localhost:3000/auth/google/callback

# JWT Configuration
JWT_SECRET=your_jwt_secret_key_min_32_chars
JWT_EXPIRES_IN=1h
JWT_REFRESH_EXPIRES_IN=7d

# Session Configuration
SESSION_SECRET=your_session_secret_min_32_chars

# OAuth Settings
OAUTH_DOMAIN_RESTRICTION=your-company.com
OAUTH_REQUIRE_DOMAIN_VERIFICATION=true
```

### Step 1.3: Google Cloud Console Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create new project or select existing
3. Enable Google+ API (for user profile information)
4. Go to "Credentials" → "Create Credentials" → "OAuth 2.0 Client IDs"
5. Configure OAuth consent screen:
   - Choose "External" for testing or "Internal" for Google Workspace
   - Fill in required fields (app name, user support email, etc.)
6. Create OAuth 2.0 credentials:
   - Application type: Web application
   - Authorized redirect URIs: `http://localhost:3000/auth/google/callback`
   - Authorized JavaScript origins: `http://localhost:3000`
7. Download credentials and update environment variables

## Phase 2: Core OAuth Implementation

### Step 2.1: Create OAuth Configuration

**File:** `src/config/oauth.ts`

```typescript
export interface OAuthConfig {
  google: {
    clientId: string;
    clientSecret: string;
    callbackUrl: string;
  };
  jwt: {
    secret: string;
    expiresIn: string;
    refreshExpiresIn: string;
  };
  session: {
    secret: string;
  };
  domain: {
    restriction?: string;
    requireVerification: boolean;
  };
}

export function loadOAuthConfig(): OAuthConfig {
  // Implementation to load and validate OAuth configuration
}
```

### Step 2.2: Create JWT Service

**File:** `src/services/jwt-service.ts`

```typescript
export interface UserToken {
  sub: string; // Google user ID
  email: string;
  name: string;
  domain: string;
  iat: number;
  exp: number;
}

export class JWTService {
  generateAccessToken(user: GoogleUser): string;
  generateRefreshToken(user: GoogleUser): string;
  verifyToken(token: string): UserToken | null;
  refreshToken(
    refreshToken: string
  ): { accessToken: string; refreshToken: string } | null;
}
```

### Step 2.3: Create OAuth Middleware

**File:** `src/middleware/oauth.ts`

```typescript
export class OAuthMiddleware {
  static authenticateToken(
    req: Request,
    res: Response,
    next: NextFunction
  ): void;
  static requireDomain(req: Request, res: Response, next: NextFunction): void;
  static validateGoogleUser(profile: any): GoogleUser | null;
}
```

### Step 2.4: Create OAuth Routes

**File:** `src/routes/oauth.ts`

```typescript
export const oauthRoutes = {
  "/auth/google": "Initiate Google OAuth flow",
  "/auth/google/callback": "Handle Google OAuth callback",
  "/auth/verify": "Verify JWT token",
  "/auth/refresh": "Refresh JWT token",
  "/auth/logout": "Logout and invalidate tokens",
};
```

## Phase 3: Authentication System Replacement

### Step 3.1: Remove AUTH_TOKEN Dependencies

**Files to modify:**

- `src/http-server.ts`
- `src/http-server-single-session.ts`
- `src/utils/auth.ts`

**Changes:**

1. Remove `loadAuthToken()` function
2. Remove `validateEnvironment()` AUTH_TOKEN checks
3. Remove static token validation logic
4. Remove AUTH_TOKEN environment variable usage

### Step 3.2: Update HTTP Server Authentication

**File:** `src/http-server.ts`

**Replace authentication logic in `/mcp` endpoint:**

```typescript
// OLD: Static token validation
const token = authHeader.slice(7).trim();
if (token !== authToken) {
  /* reject */
}

// NEW: JWT token validation
const token = authHeader.slice(7).trim();
const userToken = jwtService.verifyToken(token);
if (!userToken) {
  /* reject */
}
```

### Step 3.3: Update Single Session Server

**File:** `src/http-server-single-session.ts`

**Replace authentication logic:**

```typescript
// OLD: Static token validation
if (token !== this.authToken) {
  /* reject */
}

// NEW: JWT token validation
const userToken = jwtService.verifyToken(token);
if (!userToken) {
  /* reject */
}
```

### Step 3.4: Update Auth Manager

**File:** `src/utils/auth.ts`

**Replace static token validation with JWT validation:**

```typescript
export class AuthManager {
  validateToken(token: string | undefined): UserToken | null {
    if (!token) return null;
    return jwtService.verifyToken(token);
  }

  // Remove static token methods
  // Add JWT-specific methods
}
```

## Phase 4: OAuth Flow Implementation

### Step 4.1: Google OAuth Strategy

**File:** `src/strategies/google-strategy.ts`

```typescript
import { Strategy as GoogleStrategy } from "passport-google-oauth20";

export const googleStrategy = new GoogleStrategy(
  {
    clientID: process.env.GOOGLE_CLIENT_ID!,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
    callbackURL: process.env.GOOGLE_CALLBACK_URL!,
  },
  async (accessToken, refreshToken, profile, done) => {
    // Validate user domain
    // Create or update user
    // Generate JWT tokens
    // Return user with tokens
  }
);
```

### Step 4.2: OAuth Route Handlers

**File:** `src/routes/oauth-handlers.ts`

```typescript
export const oauthHandlers = {
  initiateGoogleAuth: (req: Request, res: Response) => {
    // Redirect to Google OAuth
  },

  handleGoogleCallback: async (req: Request, res: Response) => {
    // Process Google callback
    // Generate JWT tokens
    // Return tokens to client
  },

  verifyToken: (req: Request, res: Response) => {
    // Verify JWT token
    // Return user information
  },

  refreshToken: (req: Request, res: Response) => {
    // Refresh JWT token
    // Return new tokens
  },
};
```

### Step 4.3: Session Management

**File:** `src/middleware/session.ts`

```typescript
export const sessionConfig = {
  secret: process.env.SESSION_SECRET!,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === "production",
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
  },
};
```

## Phase 5: MCP Client Integration

### Step 5.1: Update MCP Client Configuration

**File:** `docs/CLAUDE_OAUTH_SETUP.md`

```json
{
  "mcpServers": {
    "n8n-oauth": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "https://your-server.com/mcp",
        "--header",
        "Authorization: Bearer YOUR_JWT_TOKEN_HERE"
      ]
    }
  }
}
```

### Step 5.2: OAuth Token Acquisition Flow

**File:** `docs/OAUTH_TOKEN_ACQUISITION.md`

```markdown
1. Navigate to https://your-server.com/auth/google
2. Complete Google OAuth flow
3. Receive JWT access token and refresh token
4. Use access token in MCP client configuration
5. Refresh token when access token expires
```

### Step 5.3: Update Documentation

**Files to update:**

- `README.md` - Add OAuth setup instructions
- `docs/HTTP_DEPLOYMENT.md` - Replace AUTH_TOKEN with OAuth
- `docs/RAILWAY_DEPLOYMENT.md` - Update deployment instructions
- `docs/VS_CODE_PROJECT_SETUP.md` - Update VS Code configuration

## Phase 6: Testing and Validation

### Step 6.1: Unit Tests

**File:** `tests/unit/oauth.test.ts`

```typescript
describe("OAuth Integration", () => {
  test("JWT token generation and validation");
  test("Google OAuth callback handling");
  test("Domain restriction validation");
  test("Token refresh mechanism");
  test("MCP endpoint authentication");
});
```

### Step 6.2: Integration Tests

**File:** `tests/integration/oauth-flow.test.ts`

```typescript
describe("OAuth Flow Integration", () => {
  test("Complete OAuth flow from initiation to MCP access");
  test("Token expiration and refresh handling");
  test("Domain verification for Google Workspace");
  test("MCP client authentication with JWT");
});
```

### Step 6.3: End-to-End Tests

**File:** `tests/e2e/oauth-mcp.test.ts`

```typescript
describe("OAuth MCP End-to-End", () => {
  test("Claude Desktop integration with OAuth");
  test("ChatGPT integration with OAuth");
  test("Token lifecycle management");
  test("Error handling and recovery");
});
```

## Phase 7: Migration and Deployment

### Step 7.1: Migration Script

**File:** `scripts/migrate-to-oauth.ts`

```typescript
// Script to migrate existing AUTH_TOKEN configurations
// Update environment variables
// Validate OAuth configuration
// Test new authentication flow
```

### Step 7.2: Environment Variable Updates

**File:** `.env.example`

```env
# Remove AUTH_TOKEN
# Add OAuth configuration
# Add JWT configuration
# Add session configuration
```

### Step 7.3: Docker Configuration Updates

**File:** `docker-compose.yml`

```yaml
# Remove AUTH_TOKEN environment variable
# Add OAuth environment variables
# Add session volume for session storage
```

### Step 7.4: Deployment Documentation

**File:** `docs/OAUTH_DEPLOYMENT.md`

```markdown
# OAuth Deployment Guide

1. Google Cloud Console setup
2. Environment variable configuration
3. OAuth callback URL configuration
4. MCP client setup with OAuth
5. Troubleshooting guide
```

## Phase 8: Cleanup and Optimization

### Step 8.1: Remove Deprecated Code

- Remove `AUTH_TOKEN` references
- Remove static token validation
- Remove unused authentication utilities
- Clean up environment variable handling

### Step 8.2: Update Error Handling

- Add OAuth-specific error messages
- Improve JWT validation error handling
- Add domain verification error handling
- Update logging for OAuth events

### Step 8.3: Performance Optimization

- Implement token caching
- Optimize JWT validation
- Add rate limiting for OAuth endpoints
- Implement session cleanup

## Implementation Order

1. **Phase 1-2**: Dependencies and core OAuth implementation
2. **Phase 3**: Replace AUTH_TOKEN system
3. **Phase 4**: Implement OAuth flow
4. **Phase 5**: Update MCP client integration
5. **Phase 6**: Testing and validation
6. **Phase 7**: Migration and deployment
7. **Phase 8**: Cleanup and optimization

## Success Criteria

- [ ] AUTH_TOKEN authentication completely removed
- [ ] Google OAuth 2.0 flow working end-to-end
- [ ] JWT tokens generated and validated correctly
- [ ] Domain restriction working for Google Workspace
- [ ] MCP clients can authenticate with OAuth
- [ ] All existing functionality preserved
- [ ] Comprehensive test coverage
- [ ] Documentation updated
- [ ] Migration path documented

## Risk Mitigation

- **Backward Compatibility**: Maintain API compatibility during transition
- **Rollback Plan**: Keep AUTH_TOKEN as fallback during initial deployment
- **Testing**: Comprehensive testing at each phase
- **Monitoring**: Add OAuth-specific logging and monitoring
- **Documentation**: Clear migration and troubleshooting guides

## Estimated Timeline

- **Phase 1-2**: 2-3 days
- **Phase 3**: 1-2 days
- **Phase 4**: 2-3 days
- **Phase 5**: 1-2 days
- **Phase 6**: 2-3 days
- **Phase 7**: 1-2 days
- **Phase 8**: 1 day

**Total Estimated Time**: 10-16 days

## Notes for AI Implementation

- Each step should be implemented and tested before moving to the next
- Use TypeScript interfaces for type safety
- Implement comprehensive error handling
- Add detailed logging for debugging
- Follow existing code patterns and conventions
- Maintain backward compatibility during transition
- Test with both Claude Desktop and ChatGPT clients
