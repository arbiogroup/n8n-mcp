import { JWTService, UserToken } from "../services/jwt-service";
import { GoogleUser } from "../config/oauth";

export class AuthManager {
  private jwtService: JWTService;

  constructor(jwtService: JWTService) {
    this.jwtService = jwtService;
  }

  /**
   * Validate JWT token
   */
  validateToken(token: string | undefined): UserToken | null {
    if (!token) {
      return null;
    }

    return this.jwtService.verifyToken(token);
  }

  /**
   * Generate access token for user
   */
  generateAccessToken(user: GoogleUser): string {
    return this.jwtService.generateAccessToken(user);
  }

  /**
   * Generate refresh token for user
   */
  generateRefreshToken(user: GoogleUser): string {
    return this.jwtService.generateRefreshToken(user);
  }

  /**
   * Generate both access and refresh tokens
   */
  generateTokenPair(user: GoogleUser) {
    return this.jwtService.generateTokenPair(user);
  }

  /**
   * Refresh access token using refresh token
   */
  refreshToken(refreshToken: string) {
    return this.jwtService.refreshToken(refreshToken);
  }

  /**
   * Extract user information from token
   */
  getUserFromToken(token: string): GoogleUser | null {
    return this.jwtService.getUserFromToken(token);
  }

  /**
   * Check if token is expired
   */
  isTokenExpired(token: string): boolean {
    return this.jwtService.isTokenExpired(token);
  }

  /**
   * Validate domain for user
   */
  validateDomain(user: GoogleUser): boolean {
    return this.jwtService.validateDomain(user);
  }
}
