import { Router, Request, Response } from 'express';
import { OAuthService } from '../services/oauth-service';
import { 
  TokenRequest,
  TokenResponse,
  InvalidRequestError,
  InvalidClientError,
  InvalidGrantError,
  UnsupportedGrantTypeError
} from '../models/oauth-models';
import { logger } from '../utils/logger';

export function createTokenRouter(oauthService: OAuthService): Router {
  const router = Router();

  /**
   * POST /oauth/token - Token endpoint
   * 
   * This endpoint handles:
   * 1. Authorization code exchange for access tokens
   * 2. Refresh token exchange for new access tokens
   * 
   * Supports OAuth 2.1 with PKCE validation
   */
  router.post('/token', async (req: Request, res: Response): Promise<any> => {
    try {
      logger.info('Raw token request received', {
        method: req.method,
        url: req.url,
        headers: req.headers,
        contentType: req.get('content-type'),
        bodyKeys: Object.keys(req.body || {}),
        rawBody: JSON.stringify(req.body)
      });

      const {
        grant_type,
        code,
        redirect_uri,
        client_id,
        client_secret,
        code_verifier,
        refresh_token,
        scope
      } = req.body as TokenRequest;

      logger.info('Parsed token request', {
        grant_type,
        client_id,
        has_code: !!code,
        code_length: code?.length,
        has_refresh_token: !!refresh_token,
        redirect_uri,
        code_verifier: !!code_verifier,
        allParams: {
          grant_type,
          client_id,
          redirect_uri,
          code: code ? `${code.substring(0, 8)}...` : undefined,
          code_verifier: code_verifier ? 'present' : undefined
        }
      });

      // Validate grant_type
      if (!grant_type) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Missing grant_type parameter'
        });
      }

      // Validate client_id
      if (!client_id) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Missing client_id parameter'
        });
      }

      // Handle authorization_code grant
      if (grant_type === 'authorization_code') {
        // Validate required parameters for authorization code grant
        if (!code || !redirect_uri) {
          return res.status(400).json({
            error: 'invalid_request',
            error_description: 'Missing required parameters: code, redirect_uri'
          });
        }

        try {
          const tokenResponse = await oauthService.exchangeAuthorizationCode({
            code,
            clientId: client_id,
            clientSecret: client_secret,
            redirectUri: redirect_uri,
            codeVerifier: code_verifier
          });

          logger.info('Authorization code exchanged successfully', {
            client_id,
            expires_in: tokenResponse.expires_in
          });

          // Return token response
          return res.json({
            access_token: tokenResponse.access_token,
            token_type: tokenResponse.token_type,
            expires_in: tokenResponse.expires_in,
            refresh_token: tokenResponse.refresh_token,
            scope: tokenResponse.scope
          } as TokenResponse);

        } catch (error) {
          logger.warn('Authorization code exchange failed:', error);

          if (error instanceof InvalidClientError) {
            return res.status(401).json({
              error: 'invalid_client',
              error_description: error.errorDescription || 'Client authentication failed'
            });
          }

          if (error instanceof InvalidGrantError) {
            return res.status(400).json({
              error: 'invalid_grant',
              error_description: error.errorDescription || 'Invalid or expired authorization code'
            });
          }

          if (error instanceof InvalidRequestError) {
            return res.status(400).json({
              error: 'invalid_request',
              error_description: error.errorDescription || 'Invalid request'
            });
          }

          // Generic error
          return res.status(500).json({
            error: 'server_error',
            error_description: 'Token exchange failed'
          });
        }
      }

      // Handle refresh_token grant
      if (grant_type === 'refresh_token') {
        // Validate required parameters for refresh token grant
        if (!refresh_token) {
          return res.status(400).json({
            error: 'invalid_request',
            error_description: 'Missing refresh_token parameter'
          });
        }

        try {
          const tokenResponse = await oauthService.refreshTokens({
            refreshToken: refresh_token,
            clientId: client_id,
            clientSecret: client_secret,
            scope
          });

          logger.info('Refresh token exchanged successfully', {
            client_id,
            expires_in: tokenResponse.expires_in
          });

          // Return token response
          return res.json({
            access_token: tokenResponse.access_token,
            token_type: tokenResponse.token_type,
            expires_in: tokenResponse.expires_in,
            refresh_token: tokenResponse.refresh_token,
            scope: tokenResponse.scope
          } as TokenResponse);

        } catch (error) {
          logger.warn('Refresh token exchange failed:', error);

          if (error instanceof InvalidClientError) {
            return res.status(401).json({
              error: 'invalid_client',
              error_description: error.errorDescription || 'Client authentication failed'
            });
          }

          if (error instanceof InvalidGrantError) {
            return res.status(400).json({
              error: 'invalid_grant',
              error_description: error.errorDescription || 'Invalid or expired refresh token'
            });
          }

          if (error instanceof InvalidRequestError) {
            return res.status(400).json({
              error: 'invalid_request',
              error_description: error.errorDescription || 'Invalid request'
            });
          }

          // Generic error
          return res.status(500).json({
            error: 'server_error',
            error_description: 'Token refresh failed'
          });
        }
      }

      // Unsupported grant type
      return res.status(400).json({
        error: 'unsupported_grant_type',
        error_description: `Grant type '${grant_type}' is not supported. Supported types: authorization_code, refresh_token`
      });

    } catch (error) {
      logger.error('Token endpoint error:', error);

      res.status(500).json({
        error: 'server_error',
        error_description: 'Internal server error'
      });
    }
  });

  /**
   * POST /oauth/revoke - Token revocation endpoint
   * 
   * Allows clients to revoke access tokens or refresh tokens
   */
  router.post('/revoke', async (req: Request, res: Response): Promise<any> => {
    try {
      const { token, token_type_hint, client_id, client_secret } = req.body;

      logger.info('Token revocation request received', {
        client_id,
        token_type_hint,
        has_token: !!token
      });

      // Validate required parameters
      if (!token) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Missing token parameter'
        });
      }

      if (!client_id) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Missing client_id parameter'
        });
      }

      try {
        await oauthService.revokeToken(token, client_id, client_secret);

        logger.info('Token revoked successfully', { client_id });

        // OAuth spec says to return 200 OK even if token was already invalid
        return res.status(200).json({});

      } catch (error) {
        logger.warn('Token revocation failed:', error);

        if (error instanceof InvalidClientError) {
          return res.status(401).json({
            error: 'invalid_client',
            error_description: error.errorDescription || 'Client authentication failed'
          });
        }

        // For other errors, still return success per OAuth spec
        return res.status(200).json({});
      }

    } catch (error) {
      logger.error('Token revocation endpoint error:', error);

      res.status(500).json({
        error: 'server_error',
        error_description: 'Internal server error'
      });
    }
  });

  /**
   * POST /oauth/introspect - Token introspection endpoint
   * 
   * Allows resource servers to validate tokens and get metadata
   */
  router.post('/introspect', async (req: Request, res: Response): Promise<any> => {
    try {
      const { token, token_type_hint } = req.body;

      logger.debug('Token introspection request received', {
        token_type_hint,
        has_token: !!token
      });

      // Validate required parameters
      if (!token) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Missing token parameter'
        });
      }

      try {
        const introspectionResult = await oauthService.introspectToken(token);

        logger.debug('Token introspection completed', {
          active: introspectionResult.active,
          client_id: introspectionResult.client_id
        });

        return res.json(introspectionResult);

      } catch (error) {
        logger.warn('Token introspection failed:', error);

        // Return inactive token response on error
        return res.json({ active: false });
      }

    } catch (error) {
      logger.error('Token introspection endpoint error:', error);

      // Return inactive token response on server error
      res.json({ active: false });
    }
  });

  return router;
}
