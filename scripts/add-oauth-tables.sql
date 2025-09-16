-- Add OAuth 2.1 tables to existing nodes.db
-- Run this once to extend your current database

-- OAuth clients
CREATE TABLE IF NOT EXISTS oauth_clients (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    secret TEXT,
    redirect_uris TEXT, -- JSON array as string  
    scope TEXT DEFAULT 'mcp:read',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- OAuth tokens (both access and refresh)
CREATE TABLE IF NOT EXISTS oauth_tokens (
    token TEXT PRIMARY KEY,
    type TEXT NOT NULL CHECK(type IN ('access', 'refresh')), 
    client_id TEXT NOT NULL,
    user_email TEXT NOT NULL, -- Use Google email as user ID
    scope TEXT,
    expires_at TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- OAuth authorization codes  
CREATE TABLE IF NOT EXISTS oauth_codes (
    code TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    user_email TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    scope TEXT,
    code_challenge TEXT, -- For PKCE
    expires_at TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_oauth_tokens_client ON oauth_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_tokens_user ON oauth_tokens(user_email);
CREATE INDEX IF NOT EXISTS idx_oauth_tokens_expires ON oauth_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_oauth_codes_client ON oauth_codes(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_codes_expires ON oauth_codes(expires_at);

-- Insert a test client for development
INSERT OR IGNORE INTO oauth_clients (id, name, secret, redirect_uris, scope) 
VALUES (
    'test_client_123', 
    'Test OAuth Client',
    'test_secret_456',
    '["http://localhost:3001/callback", "http://localhost:8080/oauth/callback"]',
    'mcp:read mcp:write'
);
