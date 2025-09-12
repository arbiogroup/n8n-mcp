import { logger } from "../utils/logger";

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

export interface GoogleUser {
  id: string;
  email: string;
  name: string;
  domain: string;
  picture?: string;
}

export function loadOAuthConfig(): OAuthConfig {
  // Validate required environment variables
  const requiredVars = [
    "GOOGLE_CLIENT_ID",
    "GOOGLE_CLIENT_SECRET",
    "GOOGLE_CALLBACK_URL",
    "JWT_SECRET",
    "JWT_EXPIRES_IN",
    "JWT_REFRESH_EXPIRES_IN",
    "SESSION_SECRET",
  ];

  const missingVars = requiredVars.filter((varName) => !process.env[varName]);

  if (missingVars.length > 0) {
    logger.error("Missing required OAuth environment variables", {
      missing: missingVars,
    });
    throw new Error(
      `Missing required OAuth environment variables: ${missingVars.join(", ")}`
    );
  }

  const config: OAuthConfig = {
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
      callbackUrl: process.env.GOOGLE_CALLBACK_URL!,
    },
    jwt: {
      secret: process.env.JWT_SECRET!,
      expiresIn: process.env.JWT_EXPIRES_IN!,
      refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN!,
    },
    session: {
      secret: process.env.SESSION_SECRET!,
    },
    domain: {
      restriction: process.env.OAUTH_DOMAIN_RESTRICTION,
      requireVerification:
        process.env.OAUTH_REQUIRE_DOMAIN_VERIFICATION === "true",
    },
  };

  // Validate JWT secret length
  if (config.jwt.secret.length < 32) {
    logger.warn("JWT_SECRET should be at least 32 characters for security");
  }

  // Validate session secret length
  if (config.session.secret.length < 32) {
    logger.warn("SESSION_SECRET should be at least 32 characters for security");
  }

  logger.info("OAuth configuration loaded successfully", {
    googleClientId: config.google.clientId.substring(0, 10) + "...",
    callbackUrl: config.google.callbackUrl,
    domainRestriction: config.domain.restriction,
    requireDomainVerification: config.domain.requireVerification,
  });

  return config;
}

export function validateGoogleUser(profile: any): GoogleUser | null {
  if (!profile || !profile.id || !profile.emails || !profile.emails[0]) {
    logger.warn("Invalid Google profile data", { profile });
    return null;
  }

  const email = profile.emails[0].value;
  const domain = email.split("@")[1];

  return {
    id: profile.id,
    email: email,
    name:
      profile.displayName ||
      profile.name?.givenName + " " + profile.name?.familyName ||
      "Unknown",
    domain: domain,
    picture: profile.photos?.[0]?.value,
  };
}
