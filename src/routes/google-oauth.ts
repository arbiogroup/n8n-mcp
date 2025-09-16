import { Router, Request, Response } from 'express';
import { GoogleOAuthService } from '../services/google-oauth-service';
import { logger } from '../utils/logger';

// Session interface for Google OAuth
interface GoogleOAuthSession {
  authRequest?: {
    client_id: string;
    redirect_uri: string;
    scope?: string;
    state?: string;
    code_challenge?: string;
    code_challenge_method?: string;
  };
  user?: {
    email: string;
    name?: string;
    picture?: string;
    googleId: string;
    domain: string;
    verified: boolean;
  };
  googleTokens?: {
    access_token: string;
    refresh_token?: string;
    expires_in: number;
  };
}

// Extend Express Request to include session
interface GoogleOAuthRequest extends Request {
  session: any & GoogleOAuthSession;
}

export function createGoogleOAuthRouter(googleOAuthService: GoogleOAuthService): Router {
  const router = Router();

  /**
   * GET /auth/google/callback - Google OAuth callback
   * 
   * Handles the callback from Google OAuth after user authentication.
   * This is where users land after authenticating with Google.
   */
  router.get('/auth/google/callback', async (req: GoogleOAuthRequest, res: Response): Promise<any> => {
    try {
      const { code, state, error, error_description } = req.query;

      logger.info('Google OAuth callback received', {
        has_code: !!code,
        state,
        error: error || 'none'
      });

      // Handle OAuth errors from Google
      if (error) {
        logger.warn('Google OAuth error received', { error, error_description });

        // If there's a pending OAuth request, redirect with error
        if (req.session.authRequest) {
          const redirectUrl = new URL(req.session.authRequest.redirect_uri);
          redirectUrl.searchParams.set('error', 'access_denied');
          redirectUrl.searchParams.set('error_description', error_description as string || 'Google OAuth failed');
          if (req.session.authRequest.state) {
            redirectUrl.searchParams.set('state', req.session.authRequest.state);
          }
          
          // Clear session
          delete req.session.authRequest;
          
          return res.redirect(redirectUrl.toString());
        }

        // No pending OAuth request, show error page
        return res.status(400).render('error', {
          error: 'Google OAuth Error',
          description: error_description || 'Authentication with Google failed'
        });
      }

      // Validate authorization code
      if (!code) {
        logger.warn('Google OAuth callback missing authorization code');

        if (req.session.authRequest) {
          const redirectUrl = new URL(req.session.authRequest.redirect_uri);
          redirectUrl.searchParams.set('error', 'invalid_request');
          redirectUrl.searchParams.set('error_description', 'Missing authorization code');
          if (req.session.authRequest.state) {
            redirectUrl.searchParams.set('state', req.session.authRequest.state);
          }
          
          delete req.session.authRequest;
          return res.redirect(redirectUrl.toString());
        }

        return res.status(400).render('error', {
          error: 'Invalid Request',
          description: 'Missing authorization code from Google'
        });
      }

      // Complete Google OAuth flow
      const oauthResult = await googleOAuthService.completeOAuthFlow(code as string);

      if (!oauthResult.success) {
        logger.warn('Google OAuth flow failed', { error: oauthResult.error });

        if (req.session.authRequest) {
          const redirectUrl = new URL(req.session.authRequest.redirect_uri);
          redirectUrl.searchParams.set('error', 'access_denied');
          redirectUrl.searchParams.set('error_description', oauthResult.error || 'Google OAuth flow failed');
          if (req.session.authRequest.state) {
            redirectUrl.searchParams.set('state', req.session.authRequest.state);
          }
          
          delete req.session.authRequest;
          return res.redirect(redirectUrl.toString());
        }

        return res.status(403).render('error', {
          error: 'Access Denied',
          description: oauthResult.error || 'Google OAuth flow failed'
        });
      }

      // Store user information in session
      req.session.user = oauthResult.user!;
      req.session.googleTokens = oauthResult.tokens;

      logger.info('User authenticated via Google', {
        email: oauthResult.user!.email,
        domain: oauthResult.user!.domain,
        verified: oauthResult.user!.verified
      });

      // Check if there's a pending OAuth authorization request
      if (req.session.authRequest) {
        // Redirect to the original authorization endpoint to show consent screen
        const params = new URLSearchParams({
          response_type: 'code',
          client_id: req.session.authRequest.client_id,
          redirect_uri: req.session.authRequest.redirect_uri,
          scope: req.session.authRequest.scope || 'mcp:read',
          state: req.session.authRequest.state || '',
          ...(req.session.authRequest.code_challenge && {
            code_challenge: req.session.authRequest.code_challenge,
            code_challenge_method: req.session.authRequest.code_challenge_method || 'S256'
          })
        });
        
        return res.redirect(`/authorize?${params.toString()}`);
      }

      // No pending OAuth request, show success page
      const successHtml = `
<!DOCTYPE html>
<html>
<head>
    <title>Authentication Successful</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }
        h1 { color: #4CAF50; margin-bottom: 20px; }
        .message { color: #666; margin-bottom: 20px; }
        .user-info { background: #f8f9fa; padding: 15px; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>✓ Authentication Successful</h1>
        <div class="message">You have been successfully authenticated with Google.</div>
        <div class="user-info">
            <strong>Email:</strong> ${req.session.user!.email}<br>
            <strong>Name:</strong> ${req.session.user!.name || 'Not provided'}
        </div>
    </div>
</body>
</html>`;
      
      res.send(successHtml);

    } catch (error) {
      logger.error('Google OAuth callback error:', error);

      if (req.session.authRequest) {
        const redirectUrl = new URL(req.session.authRequest.redirect_uri);
        redirectUrl.searchParams.set('error', 'server_error');
        redirectUrl.searchParams.set('error_description', 'Internal server error during authentication');
        if (req.session.authRequest.state) {
          redirectUrl.searchParams.set('state', req.session.authRequest.state);
        }
        
        delete req.session.authRequest;
        return res.redirect(redirectUrl.toString());
      }

      res.status(500).render('error', {
        error: 'Server Error',
        description: 'An internal error occurred during authentication'
      });
    }
  });

  /**
   * GET /auth/google - Initiate Google OAuth (direct access)
   * 
   * Allows direct initiation of Google OAuth flow without OAuth client.
   * Useful for testing or direct user authentication.
   */
  router.get('/auth/google', (req: GoogleOAuthRequest, res: Response): any => {
    try {
      const { state } = req.query;

      logger.debug('Direct Google OAuth initiation requested');

      const googleAuthUrl = googleOAuthService.generateAuthUrl(state as string);
      
      res.redirect(googleAuthUrl);

    } catch (error) {
      logger.error('Error initiating Google OAuth:', error);

      res.status(500).render('error', {
        error: 'Server Error',
        description: 'Failed to initiate Google authentication'
      });
    }
  });

  /**
   * POST /auth/logout - Logout user
   * 
   * Clears user session and optionally revokes Google tokens.
   */
  router.post('/auth/logout', async (req: GoogleOAuthRequest, res: Response): Promise<any> => {
    try {
      const user = req.session.user;
      const googleTokens = req.session.googleTokens;

      logger.info('User logout requested', {
        email: user?.email
      });

      // Optionally revoke Google tokens
      if (googleTokens?.access_token) {
        try {
          await googleOAuthService.revokeToken(googleTokens.access_token);
          logger.debug('Google tokens revoked');
        } catch (error) {
          logger.warn('Failed to revoke Google tokens:', error);
          // Continue with logout even if revocation fails
        }
      }

      // Clear session
      req.session.destroy((err: any) => {
        if (err) {
          logger.error('Session destruction error:', err);
        }
      });

      res.json({
        message: 'Logged out successfully'
      });

    } catch (error) {
      logger.error('Logout error:', error);

      res.status(500).json({
        error: 'server_error',
        error_description: 'Logout failed'
      });
    }
  });

  /**
   * GET /auth/user - Get current user info
   * 
   * Returns information about the currently authenticated user.
   */
  router.get('/auth/user', (req: GoogleOAuthRequest, res: Response): any => {
    try {
      const user = req.session.user;

      if (!user) {
        return res.status(401).json({
          error: 'not_authenticated',
          error_description: 'No authenticated user'
        });
      }

      logger.debug('User info requested', { email: user.email });

      return res.json({
        email: user.email,
        name: user.name,
        picture: user.picture,
        domain: user.domain,
        verified: user.verified,
        authenticated: true
      });

    } catch (error) {
      logger.error('Error getting user info:', error);

      return res.status(500).json({
        error: 'server_error',
        error_description: 'Failed to get user information'
      });
    }
  });

  return router;
}
