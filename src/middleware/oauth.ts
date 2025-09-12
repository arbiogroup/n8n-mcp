import { Request, Response, NextFunction } from "express";
import { logger } from "../utils/logger";
import { JWTService, UserToken } from "../services/jwt-service";
import { GoogleUser, validateGoogleUser } from "../config/oauth";

// Extend Express Request interface to include user
declare global {
  namespace Express {
    interface Request {
      user?: GoogleUser;
      userToken?: UserToken;
    }
  }
}

export class OAuthMiddleware {
  private jwtService: JWTService;

  constructor(jwtService: JWTService) {
    this.jwtService = jwtService;
  }

  /**
   * Authenticate JWT token from Authorization header
   */
  authenticateToken = (
    req: Request,
    res: Response,
    next: NextFunction
  ): void => {
    const authHeader = req.headers.authorization;

    // Check if Authorization header is missing
    if (!authHeader) {
      logger.warn("Authentication failed: Missing Authorization header", {
        ip: req.ip,
        userAgent: req.get("user-agent"),
        reason: "no_auth_header",
      });
      res.status(401).json({
        jsonrpc: "2.0",
        error: {
          code: -32001,
          message: "Unauthorized: Missing Authorization header",
        },
        id: null,
      });
      return;
    }

    // Check if Authorization header has Bearer prefix
    if (!authHeader.startsWith("Bearer ")) {
      logger.warn(
        "Authentication failed: Invalid Authorization header format",
        {
          ip: req.ip,
          userAgent: req.get("user-agent"),
          reason: "invalid_auth_format",
          headerPrefix:
            authHeader.substring(0, Math.min(authHeader.length, 10)) + "...",
        }
      );
      res.status(401).json({
        jsonrpc: "2.0",
        error: {
          code: -32001,
          message: "Unauthorized: Invalid token format",
        },
        id: null,
      });
      return;
    }

    // Extract token and validate
    const token = authHeader.slice(7).trim();
    const userToken = this.jwtService.verifyToken(token);

    if (!userToken) {
      logger.warn("Authentication failed: Invalid or expired token", {
        ip: req.ip,
        userAgent: req.get("user-agent"),
        reason: "invalid_token",
      });
      res.status(401).json({
        jsonrpc: "2.0",
        error: {
          code: -32001,
          message: "Unauthorized: Invalid or expired token",
        },
        id: null,
      });
      return;
    }

    // Check if token is access token (not refresh token)
    if (userToken.type !== "access") {
      logger.warn("Authentication failed: Invalid token type", {
        ip: req.ip,
        userAgent: req.get("user-agent"),
        reason: "invalid_token_type",
        tokenType: userToken.type,
      });
      res.status(401).json({
        jsonrpc: "2.0",
        error: {
          code: -32001,
          message: "Unauthorized: Invalid token type",
        },
        id: null,
      });
      return;
    }

    // Add user information to request
    req.user = {
      id: userToken.sub,
      email: userToken.email,
      name: userToken.name,
      domain: userToken.domain,
    };
    req.userToken = userToken;

    logger.debug("Authentication successful", {
      userId: userToken.sub,
      email: userToken.email,
      domain: userToken.domain,
    });

    next();
  };

  /**
   * Validate domain restriction for Google Workspace
   */
  requireDomain = (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      logger.error("Domain validation failed: No user in request");
      res.status(401).json({
        jsonrpc: "2.0",
        error: {
          code: -32001,
          message: "Unauthorized: No user information",
        },
        id: null,
      });
      return;
    }

    const isValidDomain = this.jwtService.validateDomain(req.user);

    if (!isValidDomain) {
      logger.warn("Domain validation failed", {
        userId: req.user.id,
        email: req.user.email,
        domain: req.user.domain,
        ip: req.ip,
      });
      res.status(403).json({
        jsonrpc: "2.0",
        error: {
          code: -32002,
          message: "Forbidden: Domain not allowed",
        },
        id: null,
      });
      return;
    }

    logger.debug("Domain validation successful", {
      userId: req.user.id,
      domain: req.user.domain,
    });

    next();
  };

  /**
   * Validate Google user profile from OAuth callback
   */
  validateGoogleUser = (
    req: Request,
    res: Response,
    next: NextFunction
  ): void => {
    const profile = req.user; // Assuming passport has set this

    if (!profile) {
      logger.warn("Google user validation failed: No profile in request");
      res.status(400).json({
        error: "Bad Request",
        message: "No user profile provided",
      });
      return;
    }

    const validatedUser = validateGoogleUser(profile);

    if (!validatedUser) {
      logger.warn("Google user validation failed: Invalid profile data", {
        profile: profile,
      });
      res.status(400).json({
        error: "Bad Request",
        message: "Invalid user profile data",
      });
      return;
    }

    // Replace the profile with validated user
    req.user = validatedUser;

    logger.debug("Google user validation successful", {
      userId: validatedUser.id,
      email: validatedUser.email,
      domain: validatedUser.domain,
    });

    next();
  };

  /**
   * Optional authentication - doesn't fail if no token
   */
  optionalAuth = (req: Request, res: Response, next: NextFunction): void => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      // No authentication provided, continue without user
      next();
      return;
    }

    const token = authHeader.slice(7).trim();
    const userToken = this.jwtService.verifyToken(token);

    if (userToken && userToken.type === "access") {
      req.user = {
        id: userToken.sub,
        email: userToken.email,
        name: userToken.name,
        domain: userToken.domain,
      };
      req.userToken = userToken;
    }

    next();
  };

  /**
   * Log authentication attempts for monitoring
   */
  logAuthAttempt = (req: Request, res: Response, next: NextFunction): void => {
    const authHeader = req.headers.authorization;
    const hasToken = !!(authHeader && authHeader.startsWith("Bearer "));

    logger.info("Authentication attempt", {
      ip: req.ip,
      userAgent: req.get("user-agent"),
      hasToken,
      method: req.method,
      path: req.path,
      timestamp: new Date().toISOString(),
    });

    next();
  };
}
