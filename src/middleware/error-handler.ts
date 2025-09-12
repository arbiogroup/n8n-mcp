import { Request, Response, NextFunction } from "express";
import { logger } from "../utils/logger";

export interface OAuthError extends Error {
  statusCode?: number;
  code?: string;
  details?: any;
}

export class OAuthErrorHandler {
  /**
   * Handle OAuth-specific errors
   */
  static handleOAuthError = (
    error: OAuthError,
    req: Request,
    res: Response,
    next: NextFunction
  ): void => {
    logger.error("OAuth error occurred", {
      error: error.message,
      code: error.code,
      statusCode: error.statusCode,
      path: req.path,
      method: req.method,
      userAgent: req.get("user-agent"),
      ip: req.ip,
    });

    // Determine status code
    const statusCode = error.statusCode || 500;

    // Determine error code
    let errorCode = error.code || "OAUTH_ERROR";

    // Map common OAuth errors to user-friendly messages
    let message = error.message;
    if (error.message.includes("Invalid token")) {
      errorCode = "INVALID_TOKEN";
      message = "The provided token is invalid or expired";
    } else if (error.message.includes("Token expired")) {
      errorCode = "TOKEN_EXPIRED";
      message = "The token has expired. Please refresh your authentication";
    } else if (error.message.includes("Domain not authorized")) {
      errorCode = "DOMAIN_NOT_AUTHORIZED";
      message = "Your domain is not authorized to access this service";
    } else if (error.message.includes("Invalid user profile")) {
      errorCode = "INVALID_USER_PROFILE";
      message = "Unable to process user profile information";
    } else if (error.message.includes("Google OAuth")) {
      errorCode = "GOOGLE_OAUTH_ERROR";
      message = "Authentication with Google failed. Please try again";
    }

    res.status(statusCode).json({
      success: false,
      error: {
        code: errorCode,
        message: message,
        ...(process.env.NODE_ENV === "development" && {
          details: error.details,
        }),
      },
      timestamp: new Date().toISOString(),
    });
  };

  /**
   * Handle JWT-specific errors
   */
  static handleJWTError = (
    error: any,
    req: Request,
    res: Response,
    next: NextFunction
  ): void => {
    logger.error("JWT error occurred", {
      error: error.message,
      path: req.path,
      method: req.method,
    });

    let statusCode = 401;
    let errorCode = "JWT_ERROR";
    let message = "Token validation failed";

    if (error.name === "TokenExpiredError") {
      errorCode = "TOKEN_EXPIRED";
      message = "The token has expired. Please refresh your authentication";
    } else if (error.name === "JsonWebTokenError") {
      errorCode = "INVALID_TOKEN";
      message = "The provided token is invalid";
    } else if (error.name === "NotBeforeError") {
      errorCode = "TOKEN_NOT_ACTIVE";
      message = "The token is not yet active";
    }

    res.status(statusCode).json({
      success: false,
      error: {
        code: errorCode,
        message: message,
      },
      timestamp: new Date().toISOString(),
    });
  };

  /**
   * Handle Passport authentication errors
   */
  static handlePassportError = (
    error: any,
    req: Request,
    res: Response,
    next: NextFunction
  ): void => {
    logger.error("Passport authentication error", {
      error: error.message,
      path: req.path,
      method: req.method,
    });

    res.status(401).json({
      success: false,
      error: {
        code: "AUTHENTICATION_FAILED",
        message: "Authentication failed. Please try again",
      },
      timestamp: new Date().toISOString(),
    });
  };

  /**
   * Handle general application errors
   */
  static handleGeneralError = (
    error: any,
    req: Request,
    res: Response,
    next: NextFunction
  ): void => {
    logger.error("General application error", {
      error: error.message,
      stack: error.stack,
      path: req.path,
      method: req.method,
    });

    const statusCode = error.statusCode || 500;
    const isDevelopment = process.env.NODE_ENV === "development";

    res.status(statusCode).json({
      success: false,
      error: {
        code: "INTERNAL_ERROR",
        message: isDevelopment ? error.message : "An internal error occurred",
        ...(isDevelopment && { stack: error.stack }),
      },
      timestamp: new Date().toISOString(),
    });
  };

  /**
   * Handle 404 errors for OAuth routes
   */
  static handleNotFound = (
    req: Request,
    res: Response,
    next: NextFunction
  ): void => {
    if (req.path.startsWith("/auth/")) {
      res.status(404).json({
        success: false,
        error: {
          code: "OAUTH_ENDPOINT_NOT_FOUND",
          message: `OAuth endpoint not found: ${req.method} ${req.path}`,
        },
        availableEndpoints: [
          "GET /auth/google",
          "GET /auth/google/callback",
          "GET /auth/verify",
          "POST /auth/refresh",
          "POST /auth/logout",
          "GET /auth/config",
        ],
        timestamp: new Date().toISOString(),
      });
    } else {
      next();
    }
  };
}
