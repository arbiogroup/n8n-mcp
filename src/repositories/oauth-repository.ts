import { DatabaseAdapter } from '../database/database-adapter';
import { 
  OAuthClient, 
  OAuthToken, 
  OAuthAuthorizationCode,
  OAuthClientRow,
  OAuthTokenRow,
  OAuthCodeRow,
  InvalidClientError,
  InvalidGrantError 
} from '../models/oauth-models';
import { logger } from '../utils/logger';

export class OAuthRepository {
  constructor(private db: DatabaseAdapter) {}

  // Client management
  async createClient(client: {
    id: string;
    name: string;
    secret?: string;
    redirectUris: string[];
    scope?: string;
    clientType?: 'public' | 'confidential';
  }): Promise<OAuthClient> {
    try {
      const stmt = this.db.prepare(`
        INSERT INTO oauth_clients (id, name, secret, redirect_uris, scope) 
        VALUES (?, ?, ?, ?, ?)
      `);
      
      stmt.run(
        client.id,
        client.name,
        client.secret || null,
        JSON.stringify(client.redirectUris),
        client.scope || 'mcp:read'
      );
      
      const createdClient = await this.getClient(client.id);
      if (!createdClient) {
        throw new Error('Failed to create client');
      }
      
      logger.info(`OAuth client created: ${client.id}`);
      return createdClient;
    } catch (error) {
      logger.error('Error creating OAuth client:', error);
      throw error;
    }
  }

  async getClient(clientId: string): Promise<OAuthClient | null> {
    try {
      const stmt = this.db.prepare('SELECT * FROM oauth_clients WHERE id = ?');
      const row = stmt.get(clientId) as OAuthClientRow | undefined;
      
      if (!row) return null;
      
      return {
        id: row.id,
        name: row.name,
        secret: row.secret || undefined,
        redirectUris: JSON.parse(row.redirect_uris || '[]'),
        scope: row.scope,
        createdAt: row.created_at
      };
    } catch (error) {
      logger.error('Error getting OAuth client:', error);
      return null;
    }
  }

  async updateClient(clientId: string, updates: Partial<Pick<OAuthClient, 'name' | 'redirectUris' | 'scope'>>): Promise<OAuthClient | null> {
    try {
      const setParts: string[] = [];
      const values: any[] = [];
      
      if (updates.name !== undefined) {
        setParts.push('name = ?');
        values.push(updates.name);
      }
      
      if (updates.redirectUris !== undefined) {
        setParts.push('redirect_uris = ?');
        values.push(JSON.stringify(updates.redirectUris));
      }
      
      if (updates.scope !== undefined) {
        setParts.push('scope = ?');
        values.push(updates.scope);
      }
      
      if (setParts.length === 0) {
        return this.getClient(clientId);
      }
      
      values.push(clientId);
      
      const stmt = this.db.prepare(`
        UPDATE oauth_clients 
        SET ${setParts.join(', ')} 
        WHERE id = ?
      `);
      
      stmt.run(...values);
      
      logger.info(`OAuth client updated: ${clientId}`);
      return this.getClient(clientId);
    } catch (error) {
      logger.error('Error updating OAuth client:', error);
      return null;
    }
  }

  async deleteClient(clientId: string): Promise<boolean> {
    try {
      // First delete all related tokens and codes
      await this.deleteTokensByClient(clientId);
      await this.deleteCodesByClient(clientId);
      
      const stmt = this.db.prepare('DELETE FROM oauth_clients WHERE id = ?');
      const result = stmt.run(clientId);
      
      const deleted = result.changes > 0;
      if (deleted) {
        logger.info(`OAuth client deleted: ${clientId}`);
      }
      
      return deleted;
    } catch (error) {
      logger.error('Error deleting OAuth client:', error);
      return false;
    }
  }

  async listClients(): Promise<OAuthClient[]> {
    try {
      const stmt = this.db.prepare('SELECT * FROM oauth_clients ORDER BY created_at DESC');
      const rows = stmt.all() as OAuthClientRow[];
      
      return rows.map(row => ({
        id: row.id,
        name: row.name,
        secret: row.secret || undefined,
        redirectUris: JSON.parse(row.redirect_uris || '[]'),
        scope: row.scope,
        createdAt: row.created_at
      }));
    } catch (error) {
      logger.error('Error listing OAuth clients:', error);
      return [];
    }
  }

  // Authorization codes
  async createAuthCode(data: {
    code: string;
    clientId: string;
    userEmail: string;
    redirectUri: string;
    scope?: string;
    codeChallenge?: string;
    codeChallengeMethod?: string;
    expiresAt: string;
  }): Promise<void> {
    try {
      const stmt = this.db.prepare(`
        INSERT INTO oauth_codes (code, client_id, user_email, redirect_uri, scope, code_challenge, expires_at) 
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `);
      
      stmt.run(
        data.code,
        data.clientId,
        data.userEmail,
        data.redirectUri,
        data.scope || null,
        data.codeChallenge || null,
        data.expiresAt
      );
      
      logger.debug(`Authorization code created for client: ${data.clientId}`);
    } catch (error) {
      logger.error('Error creating authorization code:', error);
      throw error;
    }
  }

  async getAuthCode(code: string): Promise<OAuthAuthorizationCode | null> {
    try {
      const stmt = this.db.prepare('SELECT * FROM oauth_codes WHERE code = ?');
      const row = stmt.get(code) as OAuthCodeRow | undefined;
      
      if (!row) return null;
      
      // Check if expired
      if (new Date(row.expires_at) < new Date()) {
        await this.deleteAuthCode(code);
        return null;
      }
      
      return {
        code: row.code,
        clientId: row.client_id,
        userEmail: row.user_email,
        redirectUri: row.redirect_uri,
        scope: row.scope || undefined,
        codeChallenge: row.code_challenge || undefined,
        expiresAt: row.expires_at,
        createdAt: row.created_at
      };
    } catch (error) {
      logger.error('Error getting authorization code:', error);
      return null;
    }
  }

  async deleteAuthCode(code: string): Promise<void> {
    try {
      const stmt = this.db.prepare('DELETE FROM oauth_codes WHERE code = ?');
      stmt.run(code);
      logger.debug(`Authorization code deleted: ${code.substring(0, 10)}...`);
    } catch (error) {
      logger.error('Error deleting authorization code:', error);
    }
  }

  private async deleteCodesByClient(clientId: string): Promise<void> {
    try {
      const stmt = this.db.prepare('DELETE FROM oauth_codes WHERE client_id = ?');
      stmt.run(clientId);
    } catch (error) {
      logger.error('Error deleting codes by client:', error);
    }
  }

  // Tokens (access and refresh)
  async createToken(data: {
    token: string;
    type: 'access' | 'refresh';
    clientId: string;
    userEmail: string;
    scope?: string;
    expiresAt: string;
  }): Promise<void> {
    try {
      const stmt = this.db.prepare(`
        INSERT INTO oauth_tokens (token, type, client_id, user_email, scope, expires_at) 
        VALUES (?, ?, ?, ?, ?, ?)
      `);
      
      stmt.run(
        data.token,
        data.type,
        data.clientId,
        data.userEmail,
        data.scope || null,
        data.expiresAt
      );
      
      logger.debug(`${data.type} token created for client: ${data.clientId}`);
    } catch (error) {
      logger.error('Error creating token:', error);
      throw error;
    }
  }

  async getToken(token: string): Promise<OAuthToken | null> {
    try {
      const stmt = this.db.prepare('SELECT * FROM oauth_tokens WHERE token = ?');
      const row = stmt.get(token) as OAuthTokenRow | undefined;
      
      if (!row) return null;
      
      // Check if expired
      if (new Date(row.expires_at) < new Date()) {
        await this.deleteToken(token);
        return null;
      }
      
      return {
        token: row.token,
        type: row.type,
        clientId: row.client_id,
        userEmail: row.user_email,
        scope: row.scope || undefined,
        expiresAt: row.expires_at,
        createdAt: row.created_at
      };
    } catch (error) {
      logger.error('Error getting token:', error);
      return null;
    }
  }

  async deleteToken(token: string): Promise<void> {
    try {
      const stmt = this.db.prepare('DELETE FROM oauth_tokens WHERE token = ?');
      stmt.run(token);
      logger.debug(`Token deleted: ${token.substring(0, 10)}...`);
    } catch (error) {
      logger.error('Error deleting token:', error);
    }
  }

  async deleteTokensByClient(clientId: string): Promise<void> {
    try {
      const stmt = this.db.prepare('DELETE FROM oauth_tokens WHERE client_id = ?');
      stmt.run(clientId);
    } catch (error) {
      logger.error('Error deleting tokens by client:', error);
    }
  }

  async deleteTokensByUser(userEmail: string): Promise<void> {
    try {
      const stmt = this.db.prepare('DELETE FROM oauth_tokens WHERE user_email = ?');
      stmt.run(userEmail);
      logger.info(`All tokens deleted for user: ${userEmail}`);
    } catch (error) {
      logger.error('Error deleting tokens by user:', error);
    }
  }

  async getRefreshToken(refreshToken: string): Promise<OAuthToken | null> {
    try {
      const stmt = this.db.prepare('SELECT * FROM oauth_tokens WHERE token = ? AND type = ?');
      const row = stmt.get(refreshToken, 'refresh') as OAuthTokenRow | undefined;
      
      if (!row) return null;
      
      // Check if expired
      if (new Date(row.expires_at) < new Date()) {
        await this.deleteToken(refreshToken);
        return null;
      }
      
      return {
        token: row.token,
        type: row.type,
        clientId: row.client_id,
        userEmail: row.user_email,
        scope: row.scope || undefined,
        expiresAt: row.expires_at,
        createdAt: row.created_at
      };
    } catch (error) {
      logger.error('Error getting refresh token:', error);
      return null;
    }
  }

  // Maintenance
  async cleanupExpired(): Promise<{ deletedCodes: number; deletedTokens: number }> {
    try {
      const now = new Date().toISOString();
      
      const codesStmt = this.db.prepare('DELETE FROM oauth_codes WHERE expires_at < ?');
      const codesResult = codesStmt.run(now);
      
      const tokensStmt = this.db.prepare('DELETE FROM oauth_tokens WHERE expires_at < ?');
      const tokensResult = tokensStmt.run(now);
      
      const deletedCodes = codesResult.changes;
      const deletedTokens = tokensResult.changes;
      
      if (deletedCodes > 0 || deletedTokens > 0) {
        logger.info(`Cleanup completed: ${deletedCodes} codes, ${deletedTokens} tokens removed`);
      }
      
      return { deletedCodes, deletedTokens };
    } catch (error) {
      logger.error('Error during cleanup:', error);
      return { deletedCodes: 0, deletedTokens: 0 };
    }
  }

  // Statistics and health check
  async getStats(): Promise<{
    clientCount: number;
    activeTokenCount: number;
    pendingCodeCount: number;
    nodeCount: number;
  }> {
    try {
      const clientStmt = this.db.prepare('SELECT COUNT(*) as count FROM oauth_clients');
      const clientResult = clientStmt.get() as { count: number };
      
      const tokenStmt = this.db.prepare('SELECT COUNT(*) as count FROM oauth_tokens WHERE expires_at > ?');
      const tokenResult = tokenStmt.get(new Date().toISOString()) as { count: number };
      
      const codeStmt = this.db.prepare('SELECT COUNT(*) as count FROM oauth_codes WHERE expires_at > ?');
      const codeResult = codeStmt.get(new Date().toISOString()) as { count: number };
      
      const nodeStmt = this.db.prepare('SELECT COUNT(*) as count FROM nodes');
      const nodeResult = nodeStmt.get() as { count: number };
      
      return {
        clientCount: clientResult.count,
        activeTokenCount: tokenResult.count,
        pendingCodeCount: codeResult.count,
        nodeCount: nodeResult.count
      };
    } catch (error) {
      logger.error('Error getting OAuth stats:', error);
      return {
        clientCount: 0,
        activeTokenCount: 0,
        pendingCodeCount: 0,
        nodeCount: 0
      };
    }
  }
}
