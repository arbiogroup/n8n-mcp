import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { logger } from "../utils/logger";
import { OAuthConfig, GoogleUser, validateGoogleUser } from "../config/oauth";

export function createGoogleStrategy(config: OAuthConfig) {
  return new GoogleStrategy(
    {
      clientID: config.google.clientId,
      clientSecret: config.google.clientSecret,
      callbackURL: config.google.callbackUrl,
      scope: ["openid", "email", "profile"],
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        logger.info("Google OAuth strategy callback", {
          profileId: profile.id,
          email: profile.emails?.[0]?.value,
          displayName: profile.displayName,
        });

        // Validate the Google profile
        const validatedUser = validateGoogleUser(profile);

        if (!validatedUser) {
          logger.warn("Google OAuth strategy: Invalid profile data", {
            profileId: profile.id,
            profile: profile,
          });
          return done(new Error("Invalid user profile data"), false);
        }

        // Additional validation for Google Workspace domain
        if (config.domain.requireVerification && config.domain.restriction) {
          if (validatedUser.domain !== config.domain.restriction) {
            logger.warn("Google OAuth strategy: Domain validation failed", {
              userDomain: validatedUser.domain,
              allowedDomain: config.domain.restriction,
              email: validatedUser.email,
            });
            return done(new Error("Domain not authorized"), false);
          }
        }

        logger.info("Google OAuth strategy: User validated successfully", {
          userId: validatedUser.id,
          email: validatedUser.email,
          domain: validatedUser.domain,
        });

        // Return the validated user
        return done(null, validatedUser);
      } catch (error) {
        logger.error("Google OAuth strategy error", {
          error,
          profileId: profile.id,
        });
        return done(error, false);
      }
    }
  );
}

export function createGoogleStrategyWithTokens(config: OAuthConfig) {
  return new GoogleStrategy(
    {
      clientID: config.google.clientId,
      clientSecret: config.google.clientSecret,
      callbackURL: config.google.callbackUrl,
      scope: ["openid", "email", "profile"],
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        logger.info("Google OAuth strategy callback with tokens", {
          profileId: profile.id,
          email: profile.emails?.[0]?.value,
          hasAccessToken: !!accessToken,
          hasRefreshToken: !!refreshToken,
        });

        // Validate the Google profile
        const validatedUser = validateGoogleUser(profile);

        if (!validatedUser) {
          logger.warn("Google OAuth strategy: Invalid profile data", {
            profileId: profile.id,
          });
          return done(new Error("Invalid user profile data"), false);
        }

        // Add tokens to user object
        const userWithTokens = {
          ...validatedUser,
          accessToken,
          refreshToken,
        };

        logger.info(
          "Google OAuth strategy: User with tokens validated successfully",
          {
            userId: validatedUser.id,
            email: validatedUser.email,
            domain: validatedUser.domain,
          }
        );

        return done(null, userWithTokens);
      } catch (error) {
        logger.error("Google OAuth strategy error", {
          error,
          profileId: profile.id,
        });
        return done(error, false);
      }
    }
  );
}
