import jwt from "jsonwebtoken";
import { logger } from "../utils/logger";
import { OAuthConfig, GoogleUser } from "../config/oauth";

export interface UserToken {
  sub: string; // Google user ID
  email: string;
  name: string;
  domain: string;
  iat: number;
  exp: number;
  type: "access" | "refresh";
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export class JWTService {
  private config: OAuthConfig;

  constructor(config: OAuthConfig) {
    this.config = config;
  }

  /**
   * Generate access token for authenticated user
   */
  generateAccessToken(user: GoogleUser): string {
    const payload = {
      sub: user.id,
      email: user.email,
      name: user.name,
      domain: user.domain,
      type: "access" as const,
    };

    return jwt.sign(payload, this.config.jwt.secret, {
      expiresIn: this.config.jwt.expiresIn,
      issuer: "n8n-mcp-oauth",
      audience: "n8n-mcp-clients",
    } as jwt.SignOptions);
  }

  /**
   * Generate refresh token for authenticated user
   */
  generateRefreshToken(user: GoogleUser): string {
    const payload = {
      sub: user.id,
      email: user.email,
      name: user.name,
      domain: user.domain,
      type: "refresh" as const,
    };

    return jwt.sign(payload, this.config.jwt.secret, {
      expiresIn: this.config.jwt.refreshExpiresIn,
      issuer: "n8n-mcp-oauth",
      audience: "n8n-mcp-clients",
    } as jwt.SignOptions);
  }

  /**
   * Generate both access and refresh tokens
   */
  generateTokenPair(user: GoogleUser): TokenPair {
    const accessToken = this.generateAccessToken(user);
    const refreshToken = this.generateRefreshToken(user);

    // Calculate expiration time in seconds
    const expiresIn = this.parseExpirationTime(this.config.jwt.expiresIn);

    return {
      accessToken,
      refreshToken,
      expiresIn,
    };
  }

  /**
   * Verify and decode JWT token
   */
  verifyToken(token: string): UserToken | null {
    try {
      const decoded = jwt.verify(token, this.config.jwt.secret, {
        issuer: "n8n-mcp-oauth",
        audience: "n8n-mcp-clients",
      }) as UserToken;

      // Additional validation
      if (!decoded.sub || !decoded.email || !decoded.type) {
        logger.warn("Invalid token payload structure", { decoded });
        return null;
      }

      return decoded;
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        logger.debug("Token expired", { error: error.message });
      } else if (error instanceof jwt.JsonWebTokenError) {
        logger.debug("Invalid token", { error: error.message });
      } else {
        logger.error("Token verification error", { error });
      }
      return null;
    }
  }

  /**
   * Refresh access token using refresh token
   */
  refreshToken(
    refreshToken: string
  ): { accessToken: string; refreshToken: string } | null {
    const decoded = this.verifyToken(refreshToken);

    if (!decoded || decoded.type !== "refresh") {
      logger.warn("Invalid refresh token", { tokenType: decoded?.type });
      return null;
    }

    // Create new user object from token data
    const user: GoogleUser = {
      id: decoded.sub,
      email: decoded.email,
      name: decoded.name,
      domain: decoded.domain,
    };

    // Generate new token pair
    const newTokenPair = this.generateTokenPair(user);

    logger.info("Token refreshed successfully", {
      userId: user.id,
      email: user.email,
    });

    return newTokenPair;
  }

  /**
   * Extract user information from access token
   */
  getUserFromToken(token: string): GoogleUser | null {
    const decoded = this.verifyToken(token);

    if (!decoded || decoded.type !== "access") {
      return null;
    }

    return {
      id: decoded.sub,
      email: decoded.email,
      name: decoded.name,
      domain: decoded.domain,
    };
  }

  /**
   * Check if token is expired
   */
  isTokenExpired(token: string): boolean {
    try {
      const decoded = jwt.decode(token) as any;
      if (!decoded || !decoded.exp) {
        return true;
      }
      return Date.now() >= decoded.exp * 1000;
    } catch {
      return true;
    }
  }

  /**
   * Parse expiration time string to seconds
   */
  parseExpirationTime(expiresIn: string): number {
    const match = expiresIn.match(/^(\d+)([smhd])$/);
    if (!match) {
      return 3600; // Default to 1 hour
    }

    const value = parseInt(match[1]);
    const unit = match[2];

    switch (unit) {
      case "s":
        return value;
      case "m":
        return value * 60;
      case "h":
        return value * 60 * 60;
      case "d":
        return value * 60 * 60 * 24;
      default:
        return 3600;
    }
  }

  /**
   * Validate domain restriction
   */
  validateDomain(user: GoogleUser): boolean {
    if (!this.config.domain.requireVerification) {
      return true;
    }

    if (!this.config.domain.restriction) {
      logger.warn("Domain verification required but no restriction set");
      return false;
    }

    const allowed = user.domain === this.config.domain.restriction;

    if (!allowed) {
      logger.warn("Domain validation failed", {
        userDomain: user.domain,
        allowedDomain: this.config.domain.restriction,
      });
    }

    return allowed;
  }
}
