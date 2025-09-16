import { Router, Request, Response } from 'express';
import { OAuthService } from '../services/oauth-service';
import { GoogleOAuthService } from '../services/google-oauth-service';
import { 
  AuthorizeRequest, 
  InvalidRequestError, 
  InvalidClientError, 
  AccessDeniedError,
  UnsupportedGrantTypeError 
} from '../models/oauth-models';
import { generateState, createErrorParams, createSuccessParams } from '../utils/oauth-utils';
import { logger } from '../utils/logger';

// Session interface for authorization requests
interface AuthSession {
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
  };
  googleTokens?: {
    access_token: string;
    refresh_token?: string;
  };
}

// Extend Express Request to include session
interface AuthRequest extends Request {
  session: any & AuthSession;
}

export function createAuthorizeRouter(
  oauthService: OAuthService,
  googleOAuthService: GoogleOAuthService
): Router {
  const router = Router();

  /**
   * GET /authorize - Initiate OAuth authorization
   * 
   * This endpoint handles the authorization request from OAuth clients.
   * It validates the request, redirects to Google for user authentication,
   * and shows a consent screen.
   */
  router.get('/authorize', async (req: AuthRequest, res: Response): Promise<any> => {
    try {
      const {
        response_type,
        client_id,
        redirect_uri,
        scope,
        state,
        code_challenge,
        code_challenge_method
      } = req.query as Partial<AuthorizeRequest>;

      logger.info('OAuth authorization request received', {
        client_id,
        redirect_uri,
        scope,
        response_type,
        code_challenge: !!code_challenge,
        code_challenge_method,
        state,
        hasSession: !!req.session,
        hasUser: !!req.session?.user
      });

      // Validate response_type
      if (response_type !== 'code') {
        const errorParams = createErrorParams(
          'unsupported_response_type',
          'Only response_type=code is supported',
          state
        );
        
        if (redirect_uri) {
          const redirectUrl = new URL(redirect_uri);
          redirectUrl.search = errorParams.toString();
          return res.redirect(redirectUrl.toString());
        }
        
        return res.status(400).json({
          error: 'unsupported_response_type',
          error_description: 'Only response_type=code is supported'
        });
      }

      // Validate required parameters
      if (!client_id || !redirect_uri) {
        const errorParams = createErrorParams(
          'invalid_request',
          'Missing required parameters: client_id, redirect_uri',
          state
        );
        
        if (redirect_uri) {
          const redirectUrl = new URL(redirect_uri);
          redirectUrl.search = errorParams.toString();
          return res.redirect(redirectUrl.toString());
        }
        
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Missing required parameters: client_id, redirect_uri'
        });
      }

      // Validate authorization request (client, redirect URI, scopes, PKCE)
      try {
        const authRequest = await oauthService.createAuthorizationRequest({
          clientId: client_id,
          redirectUri: redirect_uri,
          scope,
          state,
          codeChallenge: code_challenge,
          codeChallengeMethod: code_challenge_method
        });

        // Store authorization request in session
        req.session.authRequest = {
          client_id,
          redirect_uri,
          scope,
          state,
          code_challenge,
          code_challenge_method
        };

        logger.debug('Authorization request validated', {
          client: authRequest.client.name,
          scopes: authRequest.requestedScopes
        });

      } catch (error) {
        logger.warn('Authorization request validation failed:', error);
        
        let errorCode = 'invalid_request';
        let errorDescription = 'Invalid authorization request';
        
        if (error instanceof InvalidClientError) {
          errorCode = 'invalid_client';
          errorDescription = error.errorDescription || 'Unknown client';
        } else if (error instanceof InvalidRequestError) {
          errorCode = 'invalid_request';
          errorDescription = error.errorDescription || 'Invalid request';
        }

        const errorParams = createErrorParams(errorCode, errorDescription, state);
        const redirectUrl = new URL(redirect_uri);
        redirectUrl.search = errorParams.toString();
        return res.redirect(redirectUrl.toString());
      }

      // Check if user is already authenticated
      if (req.session.user) {
        // User is authenticated, show consent screen
        const client = await oauthService.getClient(client_id);
        const clientName = client?.name || 'Unknown Application';
        const requestedScopes = scope ? scope.split(' ') : ['mcp:read'];
        
        const consentHtml = `
<!DOCTYPE html>
<html>
<head>
    <title>OAuth Authorization</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; margin-bottom: 20px; font-size: 24px; }
        .app-info { background: #f8f9fa; padding: 15px; border-radius: 4px; margin-bottom: 20px; }
        .scopes { margin: 20px 0; }
        .scope { background: #e3f2fd; padding: 8px 12px; margin: 5px 0; border-radius: 4px; font-size: 14px; }
        .user-info { color: #666; font-size: 14px; margin-bottom: 20px; }
        .buttons { display: flex; gap: 10px; margin-top: 25px; }
        button { padding: 12px 24px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
        .approve { background: #4CAF50; color: white; }
        .deny { background: #f44336; color: white; }
        .approve:hover { background: #45a049; }
        .deny:hover { background: #da190b; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Authorize Application</h1>
        <div class="app-info">
            <strong>${clientName}</strong> is requesting access to your account.
        </div>
        <div class="user-info">
            Signed in as: <strong>${req.session.user.email}</strong>
        </div>
        <div class="scopes">
            <p><strong>Requested permissions:</strong></p>
            ${requestedScopes.map(s => `<div class="scope">${s}</div>`).join('')}
        </div>
        <form method="POST" action="/authorize">
            <div class="buttons">
                <button type="submit" name="action" value="approve" class="approve">Authorize</button>
                <button type="submit" name="action" value="deny" class="deny">Deny</button>
            </div>
        </form>
    </div>
</body>
</html>`;
        
        return res.send(consentHtml);
      }

      // User not authenticated, redirect to Google OAuth
      const googleAuthUrl = googleOAuthService.generateAuthUrl(state);
      
      logger.debug('Redirecting to Google OAuth', { state });
      res.redirect(googleAuthUrl);

    } catch (error) {
      logger.error('Authorization endpoint error:', error);
      
      const redirect_uri = req.query.redirect_uri as string;
      const state = req.query.state as string;
      
      if (redirect_uri) {
        const errorParams = createErrorParams('server_error', 'Internal server error', state);
        const redirectUrl = new URL(redirect_uri);
        redirectUrl.search = errorParams.toString();
        return res.redirect(redirectUrl.toString());
      }
      
      res.status(500).json({
        error: 'server_error',
        error_description: 'Internal server error'
      });
    }
  });

  /**
   * POST /oauth/authorize - Handle consent (user approval/denial)
   * 
   * This endpoint processes the user's consent decision after they've
   * been authenticated by Google and shown the consent screen.
   */
  router.post('/authorize', async (req: AuthRequest, res: Response): Promise<any> => {
    try {
      const { action } = req.body;
      const authRequest = req.session.authRequest;
      const user = req.session.user;

      if (!authRequest || !user) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Invalid session state'
        });
      }

      logger.debug('Processing consent decision', {
        action,
        user: user.email,
        client: authRequest.client_id
      });

      // Handle denial
      if (action === 'deny') {
        const errorParams = createErrorParams(
          'access_denied',
          'User denied access',
          authRequest.state
        );
        
        const redirectUrl = new URL(authRequest.redirect_uri);
        redirectUrl.search = errorParams.toString();
        
        // Clear session
        delete req.session.authRequest;
        
        logger.info('User denied authorization', { user: user.email });
        return res.redirect(redirectUrl.toString());
      }

      // Handle approval
      if (action === 'approve') {
        // Generate authorization code
        const code = await oauthService.createAuthorizationCode({
          clientId: authRequest.client_id,
          userEmail: user.email,
          redirectUri: authRequest.redirect_uri,
          scope: authRequest.scope,
          codeChallenge: authRequest.code_challenge,
          codeChallengeMethod: authRequest.code_challenge_method
        });

        // Create success redirect
        const successParams = createSuccessParams(code, authRequest.state);
        const redirectUrl = new URL(authRequest.redirect_uri);
        redirectUrl.search = successParams.toString();


        // Clear auth request from session (keep user for future requests)
        delete req.session.authRequest;

        return res.redirect(redirectUrl.toString());
      }

      // Invalid action
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'Invalid action. Use "approve" or "deny"'
      });

    } catch (error) {
      logger.error('Authorization consent error:', error);
      
      const authRequest = req.session.authRequest;
      if (authRequest) {
        const errorParams = createErrorParams('server_error', 'Internal server error', authRequest.state);
        const redirectUrl = new URL(authRequest.redirect_uri);
        redirectUrl.search = errorParams.toString();
        return res.redirect(redirectUrl.toString());
      }
      
      res.status(500).json({
        error: 'server_error',
        error_description: 'Internal server error'
      });
    }
  });

  return router;
}
