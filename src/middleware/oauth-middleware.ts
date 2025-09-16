import { Request, Response, NextFunction } from 'express';
import { OAuthService } from '../services/oauth-service';
import { parseScopes } from '../config/oauth';
import { logger } from '../utils/logger';

// Extended request interface with OAuth user info
export interface AuthenticatedRequest extends Request {
  user?: {
    email: string;
    clientId: string;
    scope: string[];
    tokenPayload: any;
  };
  oauth?: {
    client: any;
    token: string;
  };
}

/**
 * Create OAuth authentication middleware
 */
export function createOAuthMiddleware(oauthService: OAuthService) {
  return async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
    try {
      const authHeader = req.headers.authorization;
      
      // Check for Authorization header
      if (!authHeader) {
        res.status(401).json({
          error: 'invalid_request',
          error_description: 'Missing Authorization header'
        });
        return;
      }

      // Check Bearer token format
      if (!authHeader.startsWith('Bearer ')) {
        res.status(401).json({
          error: 'invalid_request',
          error_description: 'Invalid Authorization header format. Expected: Bearer <token>'
        });
        return;
      }

      // Extract token
      const token = authHeader.slice(7).trim();
      
      if (!token) {
        res.status(401).json({
          error: 'invalid_request',
          error_description: 'Missing access token'
        });
        return;
      }

      // Validate token
      const validation = await oauthService.validateAccessToken(token);
      
      if (!validation.valid || !validation.payload || !validation.user) {
        logger.debug('OAuth token validation failed', { 
          token: token.substring(0, 10) + '...',
          ip: req.ip 
        });
        
        res.status(401).json({
          error: 'invalid_token',
          error_description: 'Invalid or expired access token'
        });
        return;
      }

      // Add user info to request
      req.user = {
        email: validation.user.email,
        clientId: validation.payload.client_id,
        scope: parseScopes(validation.payload.scope || ''),
        tokenPayload: validation.payload
      };

      req.oauth = {
        client: validation.client,
        token
      };

      logger.debug('OAuth authentication successful', {
        user: validation.user.email,
        client: validation.client?.name,
        scopes: req.user.scope
      });

      next();
    } catch (error) {
      logger.error('OAuth middleware error:', error);
      
      res.status(500).json({
        error: 'server_error',
        error_description: 'Internal authentication error'
      });
    }
  };
}

/**
 * Middleware to require specific scope
 */
export function requireScope(requiredScope: string) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({
        error: 'unauthorized',
        error_description: 'Authentication required'
      });
      return;
    }

    if (!req.user.scope.includes(requiredScope)) {
      logger.warn('Insufficient scope', {
        user: req.user.email,
        required: requiredScope,
        available: req.user.scope
      });

      res.status(403).json({
        error: 'insufficient_scope',
        error_description: `Required scope: ${requiredScope}`,
        scope: requiredScope
      });
      return;
    }

    next();
  };
}

/**
 * Middleware to require any of the specified scopes
 */
export function requireAnyScope(requiredScopes: string[]) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({
        error: 'unauthorized',
        error_description: 'Authentication required'
      });
      return;
    }

    const hasRequiredScope = requiredScopes.some(scope => req.user!.scope.includes(scope));
    
    if (!hasRequiredScope) {
      logger.warn('Insufficient scope - none of required scopes available', {
        user: req.user.email,
        required: requiredScopes,
        available: req.user.scope
      });

      res.status(403).json({
        error: 'insufficient_scope',
        error_description: `Required one of: ${requiredScopes.join(', ')}`,
        scope: requiredScopes.join(' ')
      });
      return;
    }

    next();
  };
}

/**
 * Middleware to require all specified scopes
 */
export function requireAllScopes(requiredScopes: string[]) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({
        error: 'unauthorized',
        error_description: 'Authentication required'
      });
      return;
    }

    const missingScopes = requiredScopes.filter(scope => !req.user!.scope.includes(scope));
    
    if (missingScopes.length > 0) {
      logger.warn('Insufficient scope - missing required scopes', {
        user: req.user.email,
        missing: missingScopes,
        available: req.user.scope
      });

      res.status(403).json({
        error: 'insufficient_scope',
        error_description: `Missing scopes: ${missingScopes.join(', ')}`,
        scope: requiredScopes.join(' ')
      });
      return;
    }

    next();
  };
}

/**
 * Middleware to check if user belongs to specific domain
 */
export function requireDomain(allowedDomain: string) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({
        error: 'unauthorized',
        error_description: 'Authentication required'
      });
      return;
    }

    const userDomain = req.user.email.split('@')[1];
    
    if (userDomain !== allowedDomain) {
      logger.warn('Domain restriction violation', {
        user: req.user.email,
        userDomain,
        required: allowedDomain
      });

      res.status(403).json({
        error: 'access_denied',
        error_description: `Access restricted to ${allowedDomain} domain`
      });
      return;
    }

    next();
  };
}

/**
 * Optional OAuth middleware - continues even if no token provided
 */
export function createOptionalOAuthMiddleware(oauthService: OAuthService) {
  return async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
    const authHeader = req.headers.authorization;
    
    // If no auth header, continue without authentication
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      next();
      return;
    }

    // If auth header present, try to authenticate
    const oauthMiddleware = createOAuthMiddleware(oauthService);
    
    // Wrap the OAuth middleware to catch errors and continue
    try {
      await new Promise<void>((resolve, reject) => {
        oauthMiddleware(req, res, (err?: any) => {
          if (err) reject(err);
          else resolve();
        });
      });
    } catch (error) {
      // Log the error but continue without authentication
      logger.debug('Optional OAuth authentication failed, continuing without auth:', error);
    }

    next();
  };
}

/**
 * Rate limiting middleware for OAuth endpoints
 */
export function createOAuthRateLimiter(options: {
  windowMs?: number;
  maxRequests?: number;
  keyGenerator?: (req: Request) => string;
}) {
  const windowMs = options.windowMs || 15 * 60 * 1000; // 15 minutes
  const maxRequests = options.maxRequests || 100;
  const keyGenerator = options.keyGenerator || ((req: Request) => req.ip);

  // Simple in-memory rate limiter
  const requests = new Map<string, { count: number; resetTime: number }>();

  return (req: Request, res: Response, next: NextFunction): void => {
    const key = keyGenerator(req) || req.ip || 'unknown';
    const now = Date.now();
    
    // Clean up expired entries
    for (const [k, v] of requests.entries()) {
      if (now > v.resetTime) {
        requests.delete(k);
      }
    }

    // Get or create entry for this key
    let entry = requests.get(key);
    if (!entry || now > entry.resetTime) {
      entry = { count: 0, resetTime: now + windowMs };
      requests.set(key, entry);
    }

    // Check rate limit
    if (entry.count >= maxRequests) {
      const resetIn = Math.ceil((entry.resetTime - now) / 1000);
      
      logger.warn('Rate limit exceeded', { 
        key, 
        count: entry.count, 
        resetIn 
      });

      res.status(429).json({
        error: 'rate_limit_exceeded',
        error_description: 'Too many requests',
        retry_after: resetIn
      });
      return;
    }

    // Increment counter
    entry.count++;
    
    // Add headers
    res.setHeader('X-RateLimit-Limit', maxRequests);
    res.setHeader('X-RateLimit-Remaining', Math.max(0, maxRequests - entry.count));
    res.setHeader('X-RateLimit-Reset', Math.ceil(entry.resetTime / 1000));

    next();
  };
}

/**
 * CORS middleware for OAuth endpoints
 */
export function createOAuthCORS(options: {
  allowedOrigins?: string[];
  allowCredentials?: boolean;
}) {
  const allowedOrigins = options.allowedOrigins || ['*'];
  const allowCredentials = options.allowCredentials || false;

  return (req: Request, res: Response, next: NextFunction): void => {
    const origin = req.headers.origin;
    
    // Set CORS headers
    if (allowedOrigins.includes('*') || (origin && allowedOrigins.includes(origin))) {
      res.setHeader('Access-Control-Allow-Origin', origin || '*');
    }

    if (allowCredentials) {
      res.setHeader('Access-Control-Allow-Credentials', 'true');
    }

    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    res.setHeader('Access-Control-Max-Age', '86400');

    // Handle preflight requests
    if (req.method === 'OPTIONS') {
      res.sendStatus(204);
      return;
    }

    next();
  };
}
