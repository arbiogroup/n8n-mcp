import express, { Router, Request, Response } from 'express';
import { OAuthService } from '../services/oauth-service';
import { createOAuthMiddleware, requireScope, AuthenticatedRequest } from '../middleware/oauth-middleware';
import { 
  ClientRegistrationRequest,
  ClientRegistrationResponse,
  InvalidRequestError,
  InvalidScopeError
} from '../models/oauth-models';
import { logger } from '../utils/logger';

/**
 * Enhance registration request with auto-detected client information
 */
function enhanceRegistrationRequest(request: ClientRegistrationRequest, req: Request): ClientRegistrationRequest {
  const userAgent = req.get('user-agent') || '';
  const origin = req.get('origin') || '';
  
  // Auto-detect Claude AI (keep specific client_id for compatibility)
  if (userAgent.includes('Claude') || origin.includes('claude.ai') || 
      request.redirect_uris?.some(uri => uri.includes('claude.ai'))) {
    
    logger.info('Auto-detected Claude AI client registration');
    
    return {
      ...request,
      client_name: request.client_name || 'Claude AI',
      client_type: 'public',
      redirect_uris: request.redirect_uris || [
        'https://claude.ai/api/mcp/auth_callback',
        'https://claude.ai/oauth/callback'
      ],
      // Accept any scopes requested by Claude AI - no restrictions
      scope: request.scope || '*', // Wildcard for all scopes
      client_id: '992236964315-rpq06uolni85341iafnc51q4r6sogmd6.apps.googleusercontent.com'
    };
  }
  
  // For all other clients - completely free registration
  logger.info('Processing free scope client registration');
  return {
    ...request,
    client_type: request.client_type || 'public', // Default to public for easier integration
    // Accept ANY scopes requested - no validation or restrictions
    scope: request.scope || '*' // Wildcard means "all possible scopes"
  };
}

export function createClientManagementRouter(oauthService: OAuthService): Router {
  const router = Router();
  const oauthMiddleware = createOAuthMiddleware(oauthService);

  /**
   * POST /register - Dynamic client registration (RFC 7591) - MCP Compliant
   * POST /oauth/register - Legacy path for backward compatibility
   * 
   * Allows applications to register as OAuth clients dynamically.
   * This is a public endpoint (no authentication required).
   * Supports both standard OAuth clients and automatic Claude AI detection.
   */
  // Custom JSON body parser middleware for registration
  const parseJsonBody = (req: Request, res: Response, next: any) => {
    if (req.get('content-type')?.includes('application/json')) {
      let body = '';
      req.setEncoding('utf8');
      req.on('data', (chunk) => {
        body += chunk;
      });
      req.on('end', () => {
        try {
          req.body = JSON.parse(body);
          next();
        } catch (error) {
          logger.error('❌ JSON parsing error:', error);
          res.status(400).json({
            error: 'invalid_request',
            error_description: 'Invalid JSON in request body'
          });
        }
      });
    } else {
      next();
    }
  };

  router.post('/register', parseJsonBody, async (req: Request, res: Response): Promise<any> => {
    try {
      logger.info('🔧 Client registration endpoint hit', {
        method: req.method,
        path: req.path,
        hasBody: !!req.body,
        bodyContent: req.body,
        contentType: req.get('content-type'),
        userAgent: req.get('user-agent')
      });
      
      if (!req.body) {
        logger.error('❌ No request body received');
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Request body is required'
        });
      }
      
      const registrationRequest = req.body as ClientRegistrationRequest;

      logger.info('Dynamic client registration request received', {
        client_name: registrationRequest.client_name,
        redirect_uris: registrationRequest.redirect_uris,
        client_type: registrationRequest.client_type,
        user_agent: req.get('user-agent'),
        origin: req.get('origin')
      });

      // Auto-detect common clients and enhance registration data
      const enhancedRequest = enhanceRegistrationRequest(registrationRequest, req);

      // Validate request
      if (!enhancedRequest.client_name) {
        return res.status(400).json({
          error: 'invalid_client_metadata',
          error_description: 'Missing client_name'
        });
      }

      if (!enhancedRequest.redirect_uris || !Array.isArray(enhancedRequest.redirect_uris) || enhancedRequest.redirect_uris.length === 0) {
        return res.status(400).json({
          error: 'invalid_client_metadata',
          error_description: 'Missing or invalid redirect_uris array'
        });
      }

      // Validate redirect URIs
      for (const uri of enhancedRequest.redirect_uris) {
        try {
          new URL(uri);
        } catch {
          return res.status(400).json({
            error: 'invalid_redirect_uri',
            error_description: `Invalid redirect URI: ${uri}`
          });
        }
      }

      try {
        const registrationResponse = await oauthService.registerClient(enhancedRequest);

        logger.info('Client registered successfully', {
          client_id: registrationResponse.client_id,
          client_name: registrationResponse.client_name
        });

        return res.status(201).json(registrationResponse);

      } catch (error) {
        logger.warn('Client registration failed:', error);

        if (error instanceof InvalidRequestError) {
          return res.status(400).json({
            error: 'invalid_client_metadata',
            error_description: error.errorDescription || 'Invalid client metadata'
          });
        }

        if (error instanceof InvalidScopeError) {
          return res.status(400).json({
            error: 'invalid_scope',
            error_description: error.errorDescription || 'Invalid scope'
          });
        }

        return res.status(500).json({
          error: 'server_error',
          error_description: 'Client registration failed'
        });
      }

    } catch (error) {
      logger.error('❌ Client registration error:', {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
        path: req.path,
        method: req.method
      });
      
      return res.status(500).json({
        error: 'server_error',
        error_description: 'Client registration failed - check server logs',
        debug_info: process.env.NODE_ENV === 'development' ? {
          error: error instanceof Error ? error.message : String(error)
        } : undefined
      });
    }
  });

  /**
   * GET /oauth/clients - List OAuth clients (admin only)
   * 
   * Returns a list of all registered OAuth clients.
   * Requires admin scope.
   */
  router.get('/clients', 
    oauthMiddleware, 
    requireScope('admin'), 
    async (req: AuthenticatedRequest, res: Response): Promise<any> => {
      try {
        const clients = await oauthService.listClients();

        logger.info('Client list requested', {
          admin: req.user?.email,
          client_count: clients.length
        });

        // Remove sensitive information from response
        const sanitizedClients = clients.map(client => ({
          id: client.id,
          name: client.name,
          redirectUris: client.redirectUris,
          scope: client.scope,
          clientType: client.clientType,
          createdAt: client.createdAt,
          // Don't include client secret in list
        }));

        res.json({
          clients: sanitizedClients,
          total: clients.length
        });

      } catch (error) {
        logger.error('Error listing clients:', error);

        res.status(500).json({
          error: 'server_error',
          error_description: 'Failed to list clients'
        });
      }
    }
  );

  /**
   * GET /oauth/clients/:clientId - Get specific client details
   * 
   * Returns details for a specific OAuth client.
   * Clients can access their own details, admins can access any client.
   */
  router.get('/clients/:clientId', 
    oauthMiddleware, 
    async (req: AuthenticatedRequest, res: Response): Promise<any> => {
      try {
        const { clientId } = req.params;
        const isAdmin = req.user?.scope.includes('admin');
        const isOwner = req.user?.clientId === clientId;

        // Check authorization
        if (!isAdmin && !isOwner) {
          return res.status(403).json({
            error: 'insufficient_scope',
            error_description: 'Access denied. Admin scope or client ownership required.'
          });
        }

        const client = await oauthService.getClient(clientId);

        if (!client) {
          return res.status(404).json({
            error: 'not_found',
            error_description: 'Client not found'
          });
        }

        logger.debug('Client details requested', {
          client_id: clientId,
          requester: req.user?.email,
          is_admin: isAdmin
        });

        // Return client details (include secret only for admin or owner)
        const clientResponse = {
          id: client.id,
          name: client.name,
          redirectUris: client.redirectUris,
          scope: client.scope,
          clientType: client.clientType,
          createdAt: client.createdAt,
          ...(isAdmin || isOwner ? { secret: client.secret } : {})
        };

        res.json(clientResponse);

      } catch (error) {
        logger.error('Error getting client details:', error);

        res.status(500).json({
          error: 'server_error',
          error_description: 'Failed to get client details'
        });
      }
    }
  );

  /**
   * PUT /oauth/clients/:clientId - Update client
   * 
   * Updates an OAuth client's configuration.
   * Clients can update their own details, admins can update any client.
   */
  router.put('/clients/:clientId', 
    oauthMiddleware, 
    async (req: AuthenticatedRequest, res: Response): Promise<any> => {
      try {
        const { clientId } = req.params;
        const updates = req.body;
        const isAdmin = req.user?.scope.includes('admin');
        const isOwner = req.user?.clientId === clientId;

        // Check authorization
        if (!isAdmin && !isOwner) {
          return res.status(403).json({
            error: 'insufficient_scope',
            error_description: 'Access denied. Admin scope or client ownership required.'
          });
        }

        // Validate updates
        if (updates.redirectUris && !Array.isArray(updates.redirectUris)) {
          return res.status(400).json({
            error: 'invalid_request',
            error_description: 'redirect_uris must be an array'
          });
        }

        // Validate redirect URIs if provided
        if (updates.redirectUris) {
          for (const uri of updates.redirectUris) {
            try {
              new URL(uri);
            } catch {
              return res.status(400).json({
                error: 'invalid_redirect_uri',
                error_description: `Invalid redirect URI: ${uri}`
              });
            }
          }
        }

        const updatedClient = await oauthService.updateClient(clientId, {
          name: updates.name,
          redirectUris: updates.redirectUris,
          scope: updates.scope
        });

        if (!updatedClient) {
          return res.status(404).json({
            error: 'not_found',
            error_description: 'Client not found'
          });
        }

        logger.info('Client updated', {
          client_id: clientId,
          updater: req.user?.email,
          is_admin: isAdmin
        });

        res.json({
          id: updatedClient.id,
          name: updatedClient.name,
          redirectUris: updatedClient.redirectUris,
          scope: updatedClient.scope,
          clientType: updatedClient.clientType,
          createdAt: updatedClient.createdAt
        });

      } catch (error) {
        logger.error('Error updating client:', error);

        res.status(500).json({
          error: 'server_error',
          error_description: 'Failed to update client'
        });
      }
    }
  );

  /**
   * DELETE /oauth/clients/:clientId - Delete client (admin only)
   * 
   * Deletes an OAuth client and all associated tokens.
   * Requires admin scope.
   */
  router.delete('/clients/:clientId', 
    oauthMiddleware, 
    requireScope('admin'), 
    async (req: AuthenticatedRequest, res: Response): Promise<any> => {
      try {
        const { clientId } = req.params;

        const deleted = await oauthService.deleteClient(clientId);

        if (!deleted) {
          return res.status(404).json({
            error: 'not_found',
            error_description: 'Client not found'
          });
        }

        logger.info('Client deleted', {
          client_id: clientId,
          admin: req.user?.email
        });

        res.status(204).send();

      } catch (error) {
        logger.error('Error deleting client:', error);

        res.status(500).json({
          error: 'server_error',
          error_description: 'Failed to delete client'
        });
      }
    }
  );

  /**
   * GET /oauth/stats - OAuth statistics (admin only)
   * 
   * Returns OAuth system statistics.
   * Requires admin scope.
   */
  router.get('/stats', 
    oauthMiddleware, 
    requireScope('admin'), 
    async (req: AuthenticatedRequest, res: Response): Promise<any> => {
      try {
        const stats = await oauthService.getStats();

        logger.debug('OAuth stats requested', {
          admin: req.user?.email
        });

        res.json({
          clients: stats.clientCount,
          active_tokens: stats.activeTokenCount,
          pending_codes: stats.pendingCodeCount,
          n8n_nodes: stats.nodeCount,
          timestamp: new Date().toISOString()
        });

      } catch (error) {
        logger.error('Error getting OAuth stats:', error);

        res.status(500).json({
          error: 'server_error',
          error_description: 'Failed to get statistics'
        });
      }
    }
  );

  /**
   * POST /oauth/cleanup - Cleanup expired tokens (admin only)
   * 
   * Manually trigger cleanup of expired tokens and codes.
   * Requires admin scope.
   */
  router.post('/cleanup', 
    oauthMiddleware, 
    requireScope('admin'), 
    async (req: AuthenticatedRequest, res: Response): Promise<any> => {
      try {
        const cleanupResult = await oauthService.cleanupExpiredTokens();

        logger.info('Manual cleanup triggered', {
          admin: req.user?.email,
          deleted_codes: cleanupResult.deletedCodes,
          deleted_tokens: cleanupResult.deletedTokens
        });

        res.json({
          message: 'Cleanup completed',
          deleted_codes: cleanupResult.deletedCodes,
          deleted_tokens: cleanupResult.deletedTokens,
          timestamp: new Date().toISOString()
        });

      } catch (error) {
        logger.error('Error during cleanup:', error);

        res.status(500).json({
          error: 'server_error',
          error_description: 'Cleanup failed'
        });
      }
    }
  );

  return router;
}
