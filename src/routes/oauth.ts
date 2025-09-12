import { Request, Response } from "express";
import { logger } from "../utils/logger";
import { JWTService } from "../services/jwt-service";
import { OAuthConfig, GoogleUser } from "../config/oauth";
import { OAuthError, OAuthErrorHandler } from "../middleware/error-handler";

export const oauthRoutes = {
  "/auth/google": "Initiate Google OAuth flow",
  "/auth/google/callback": "Handle Google OAuth callback",
  "/auth/verify": "Verify JWT token",
  "/auth/refresh": "Refresh JWT token",
  "/auth/logout": "Logout and invalidate tokens",
};

export class OAuthHandlers {
  private jwtService: JWTService;
  private config: OAuthConfig;

  constructor(jwtService: JWTService, config: OAuthConfig) {
    this.jwtService = jwtService;
    this.config = config;
  }

  /**
   * Initiate Google OAuth flow
   */
  initiateGoogleAuth = (req: Request, res: Response): void => {
    logger.info("Google OAuth initiation requested", {
      ip: req.ip,
      userAgent: req.get("user-agent"),
    });

    // This will be handled by Passport strategy
    // The actual redirect happens in the strategy configuration
    res.status(200).json({
      message: "Redirecting to Google OAuth",
      authUrl: this.buildGoogleAuthUrl(),
    });
  };

  /**
   * Build Google OAuth URL with state parameter for CSRF protection
   */
  private buildGoogleAuthUrl(): string {
    const state = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
    const params = new URLSearchParams({
      client_id: this.config.google.clientId,
      redirect_uri: this.config.google.callbackUrl,
      scope: 'openid email profile',
      response_type: 'code',
      state: state
    });
    return `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
  }

  /**
   * Handle Google OAuth callback
   */
  handleGoogleCallback = async (req: Request, res: Response): Promise<void> => {
    try {
      // Validate state parameter for CSRF protection
      const state = req.query.state as string;
      if (!state) {
        logger.warn("OAuth callback: Missing state parameter");
        res.status(400).json({
          error: "invalid_request",
          error_description: "Missing state parameter",
        });
        return;
      }

      const user = req.user as GoogleUser;

      if (!user) {
        logger.error("OAuth callback failed: No user in request");
        res.status(400).json({
          error: "Authentication Failed",
          message: "No user information received from Google",
        });
        return;
      }

      // Validate domain if required
      if (!this.jwtService.validateDomain(user)) {
        logger.warn("OAuth callback failed: Domain validation failed", {
          userId: user.id,
          email: user.email,
          domain: user.domain,
        });
        res.status(403).json({
          error: "Access Denied",
          message: "Your domain is not authorized to access this service",
        });
        return;
      }

      // Generate JWT tokens
      const tokenPair = this.jwtService.generateTokenPair(user);

      logger.info("OAuth callback successful", {
        userId: user.id,
        email: user.email,
        domain: user.domain,
      });

      // Return the OAuth response directly to the initiator (MCP connector)
      // This follows the OAuth 2.0 standard specification
      res.status(200).json({
        access_token: tokenPair.accessToken,
        token_type: "Bearer",
        expires_in: tokenPair.expiresIn,
        refresh_token: tokenPair.refreshToken,
        scope: "openid email profile",
        // Additional user information (non-standard but useful for MCP)
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          domain: user.domain,
        },
        // MCP-specific information
        mcp: {
          serverUrl: "http://localhost:3000/mcp",
          instructions: "Use the access_token in the Authorization header when connecting to the MCP server"
        }
      });
    } catch (error) {
      logger.error("OAuth callback error", { error });
      res.status(500).json({
        error: "Internal Server Error",
        message: "Authentication processing failed",
      });
    }
  };

  /**
   * Verify JWT token
   */
  verifyToken = (req: Request, res: Response): void => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      res.status(401).json({
        error: "Unauthorized",
        message: "No valid token provided",
      });
      return;
    }

    const token = authHeader.slice(7).trim();
    const userToken = this.jwtService.verifyToken(token);

    if (!userToken) {
      res.status(401).json({
        error: "Unauthorized",
        message: "Invalid or expired token",
      });
      return;
    }

    res.status(200).json({
      valid: true,
      user: {
        id: userToken.sub,
        email: userToken.email,
        name: userToken.name,
        domain: userToken.domain,
      },
      token: {
        type: userToken.type,
        issuedAt: new Date(userToken.iat * 1000).toISOString(),
        expiresAt: new Date(userToken.exp * 1000).toISOString(),
      },
    });
  };

  /**
   * Refresh JWT token
   */
  refreshToken = (req: Request, res: Response): void => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      res.status(400).json({
        error: "Bad Request",
        message: "Refresh token is required",
      });
      return;
    }

    const newTokens = this.jwtService.refreshToken(refreshToken);

    if (!newTokens) {
      res.status(401).json({
        error: "Unauthorized",
        message: "Invalid or expired refresh token",
      });
      return;
    }

    logger.info("Token refreshed successfully", {
      ip: req.ip,
      userAgent: req.get("user-agent"),
    });

    res.status(200).json({
      success: true,
      message: "Token refreshed successfully",
      tokens: {
        accessToken: newTokens.accessToken,
        refreshToken: newTokens.refreshToken,
        expiresIn: this.jwtService.parseExpirationTime(
          this.config.jwt.expiresIn
        ),
      },
    });
  };

  /**
   * Logout and invalidate tokens
   */
  logout = (req: Request, res: Response): void => {
    // Since we're using stateless JWT tokens, we can't actually invalidate them
    // The client should discard the tokens
    logger.info("User logout requested", {
      ip: req.ip,
      userAgent: req.get("user-agent"),
      userId: req.user?.id,
    });

    res.status(200).json({
      success: true,
      message: "Logout successful. Please discard your tokens.",
    });
  };

  /**
   * Get OAuth configuration for client
   */
  getConfig = (req: Request, res: Response): void => {
    res.status(200).json({
      google: {
        clientId: this.config.google.clientId,
        callbackUrl: this.config.google.callbackUrl,
      },
      domain: {
        restriction: this.config.domain.restriction,
        requireVerification: this.config.domain.requireVerification,
      },
    });
  };

}
