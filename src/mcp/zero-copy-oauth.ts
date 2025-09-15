import { Request, Response } from "express";
import { logger } from "../utils/logger";
import { JWTService } from "../services/jwt-service";
import { OAuthConfig, GoogleUser } from "../config/oauth";
import crypto from "crypto";

/**
 * Zero Copy-Paste OAuth Flow
 * Users only authenticate - everything else is automatic
 */
export class ZeroCopyOAuth {
  private jwtService: JWTService;
  private config: OAuthConfig;
  private activeConnections: Map<string, ConnectionSession> = new Map();

  constructor(jwtService: JWTService, config: OAuthConfig) {
    this.jwtService = jwtService;
    this.config = config;
  }

  /**
   * Main OAuth flow - users just click and authenticate
   */
  startOAuth = (req: Request, res: Response): void => {
    const clientType = req.query.client as string || 'auto';
    const sessionId = this.generateSessionId();
    
    // Store session info
    this.activeConnections.set(sessionId, {
      id: sessionId,
      clientType,
      status: 'pending',
      createdAt: new Date(),
      user: null,
      tokens: null
    });

    // Store session ID in cookie
    res.cookie('mcp_session', sessionId, { 
      httpOnly: true, 
      secure: process.env.NODE_ENV === 'production',
      maxAge: 10 * 60 * 1000 // 10 minutes
    });

    // Redirect to Google OAuth
    const state = JSON.stringify({ sessionId, clientType });
    const authUrl = this.buildGoogleAuthUrl(state);
    
    res.redirect(authUrl);
  };

  /**
   * OAuth callback - handle authentication and auto-configure client
   */
  handleCallback = async (req: Request, res: Response): Promise<void> => {
    try {
      const user = req.user as GoogleUser;
      const state = req.query.state as string;
      
      if (!user || !state) {
        return this.showError(res, 'Authentication failed');
      }

      const { sessionId } = JSON.parse(state);
      const session = this.activeConnections.get(sessionId);
      
      if (!session) {
        return this.showError(res, 'Session expired');
      }

      // Validate domain if required
      if (!this.jwtService.validateDomain(user)) {
        return this.showError(res, 'Domain not authorized');
      }

      // Generate tokens
      const tokens = this.jwtService.generateTokenPair(user);
      
      // Update session
      session.user = user;
      session.tokens = tokens;
      session.status = 'authenticated';

      // Auto-configure based on client type
      await this.autoConfigureClient(req, res, session);
      
    } catch (error) {
      logger.error('OAuth callback error', { error });
      this.showError(res, 'Authentication failed');
    }
  };

  /**
   * Auto-configure MCP client based on detected type
   */
  private async autoConfigureClient(req: Request, res: Response, session: ConnectionSession): Promise<void> {
    const userAgent = req.get('user-agent') || '';
    const clientType = this.detectClientType(userAgent, session.clientType);
    
    switch (clientType) {
      case 'claude_desktop':
        await this.configureClaudeDesktop(req, res, session);
        break;
      case 'windsurf':
        await this.configureWindsurf(req, res, session);
        break;
      case 'browser_extension':
        await this.configureBrowserExtension(req, res, session);
        break;
      default:
        await this.showManualInstructions(req, res, session);
    }
  }

  /**
   * Auto-configure Claude Desktop via deep linking
   */
  private async configureClaudeDesktop(req: Request, res: Response, session: ConnectionSession): Promise<void> {
    const baseUrl = this.getBaseUrl(req);
    const config = {
      mcpServers: {
        "n8n-docs": {
          command: "npx",
          args: [
            "-y", 
            "mcp-remote", 
            `${baseUrl}/mcp`,
            "--header",
            `Authorization: Bearer ${session.tokens!.accessToken}`
          ]
        }
      }
    };

    // Try to auto-configure via deep link
    const deepLinkUrl = `claude://mcp/configure?config=${encodeURIComponent(JSON.stringify(config))}`;
    
    res.send(this.generateSuccessHTML({
      title: 'Claude Desktop Configuration',
      message: 'Attempting to auto-configure Claude Desktop...',
      deepLinkUrl,
      config,
      instructions: [
        'If Claude Desktop opened automatically, you\'re all set!',
        'If not, click the "Open Claude Desktop" button below',
        'Claude Desktop should detect the configuration and add the server'
      ],
      actions: [
        { text: 'Open Claude Desktop', url: deepLinkUrl, primary: true },
        { text: 'Download Config File', action: 'download', data: config }
      ]
    }));
  }

  /**
   * Auto-configure Windsurf via deep linking
   */
  private async configureWindsurf(req: Request, res: Response, session: ConnectionSession): Promise<void> {
    const baseUrl = this.getBaseUrl(req);
    const config = {
      name: "n8n Documentation",
      url: `${baseUrl}/mcp`,
      auth: {
        type: "bearer",
        token: session.tokens!.accessToken
      }
    };

    // Try to auto-configure via deep link
    const deepLinkUrl = `windsurf://mcp/add?config=${encodeURIComponent(JSON.stringify(config))}`;
    
    res.send(this.generateSuccessHTML({
      title: 'Windsurf Configuration',
      message: 'Attempting to auto-configure Windsurf...',
      deepLinkUrl,
      config,
      instructions: [
        'If Windsurf opened automatically, you\'re all set!',
        'If not, click the "Open Windsurf" button below',
        'Windsurf should detect the configuration and add the MCP server'
      ],
      actions: [
        { text: 'Open Windsurf', url: deepLinkUrl, primary: true },
        { text: 'Download Config File', action: 'download', data: config }
      ]
    }));
  }

  /**
   * Configure via browser extension
   */
  private async configureBrowserExtension(req: Request, res: Response, session: ConnectionSession): Promise<void> {
    const baseUrl = this.getBaseUrl(req);
    
    // Send configuration to browser extension
    const config = {
      serverUrl: `${baseUrl}/mcp`,
      accessToken: session.tokens!.accessToken,
      serverName: 'n8n Documentation'
    };

    res.send(this.generateSuccessHTML({
      title: 'Browser Extension Configuration',
      message: 'Sending configuration to MCP browser extension...',
      config,
      instructions: [
        'The configuration has been sent to your MCP browser extension',
        'Check your extension popup to confirm the connection',
        'You should now see n8n tools available in your MCP client'
      ],
      actions: [
        { text: 'Check Extension', action: 'check_extension' },
        { text: 'Open MCP Client', action: 'open_mcp_client' }
      ]
    }));
  }

  /**
   * Show manual instructions as fallback
   */
  private async showManualInstructions(req: Request, res: Response, session: ConnectionSession): Promise<void> {
    const baseUrl = this.getBaseUrl(req);
    
    res.send(this.generateSuccessHTML({
      title: 'Manual Configuration Required',
      message: 'Your MCP client was not auto-detected. Please follow these steps:',
      config: {
        serverUrl: `${baseUrl}/mcp`,
        accessToken: session.tokens!.accessToken
      },
      instructions: [
        '1. Open your MCP client application',
        '2. Add a new MCP server with the details below',
        '3. Use the access token for authentication',
        '4. Save the configuration and restart your client'
      ],
      actions: [
        { text: 'Copy Server URL', action: 'copy', data: `${baseUrl}/mcp` },
        { text: 'Copy Access Token', action: 'copy', data: session.tokens!.accessToken },
        { text: 'Download Full Config', action: 'download', data: this.generateFullConfig(req, session) }
      ]
    }));
  }

  /**
   * Generate success page HTML
   */
  private generateSuccessHTML(options: {
    title: string;
    message: string;
    deepLinkUrl?: string;
    config: any;
    instructions: string[];
    actions: Array<{ text: string; url?: string; action?: string; data?: any; primary?: boolean }>;
  }): string {
    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${options.title} - n8n MCP</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        .container {
            background: white;
            border-radius: 12px;
            padding: 40px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            text-align: center;
        }
        .success-icon {
            font-size: 64px;
            margin-bottom: 20px;
        }
        .title {
            color: #2d3748;
            font-size: 28px;
            margin-bottom: 10px;
        }
        .message {
            color: #718096;
            font-size: 18px;
            margin-bottom: 30px;
        }
        .instructions {
            text-align: left;
            background: #f7fafc;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }
        .instruction {
            margin: 10px 0;
            padding: 10px;
            background: white;
            border-radius: 6px;
            border-left: 4px solid #667eea;
        }
        .actions {
            display: flex;
            gap: 15px;
            justify-content: center;
            flex-wrap: wrap;
            margin: 30px 0;
        }
        .btn {
            padding: 12px 24px;
            border: none;
            border-radius: 6px;
            font-size: 16px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
            transition: all 0.2s;
        }
        .btn-primary {
            background: #667eea;
            color: white;
        }
        .btn-primary:hover {
            background: #5a67d8;
            transform: translateY(-2px);
        }
        .btn-secondary {
            background: #e2e8f0;
            color: #4a5568;
        }
        .btn-secondary:hover {
            background: #cbd5e0;
        }
        .status {
            padding: 15px;
            border-radius: 6px;
            margin: 20px 0;
            display: none;
        }
        .status.success {
            background: #f0fff4;
            border: 1px solid #9ae6b4;
            color: #22543d;
        }
        .status.error {
            background: #fed7d7;
            border: 1px solid #feb2b2;
            color: #742a2a;
        }
        .config-display {
            background: #2d3748;
            color: #e2e8f0;
            padding: 15px;
            border-radius: 6px;
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 14px;
            margin: 20px 0;
            text-align: left;
            overflow-x: auto;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="success-icon">✅</div>
        <h1 class="title">${options.title}</h1>
        <p class="message">${options.message}</p>
        
        <div class="instructions">
            ${options.instructions.map(instruction => 
              `<div class="instruction">${instruction}</div>`
            ).join('')}
        </div>

        ${options.deepLinkUrl ? `
        <div class="config-display">
            Deep Link: ${options.deepLinkUrl}
        </div>
        ` : ''}

        <div class="actions">
            ${options.actions.map(action => {
              if (action.url) {
                return `<a href="${action.url}" class="btn ${action.primary ? 'btn-primary' : 'btn-secondary'}">${action.text}</a>`;
              } else if (action.action) {
                return `<button class="btn ${action.primary ? 'btn-primary' : 'btn-secondary'}" onclick="handleAction('${action.action}', ${JSON.stringify(action.data || {})})">${action.text}</button>`;
              }
              return '';
            }).join('')}
        </div>

        <div id="status" class="status"></div>
    </div>

    <script>
        function handleAction(action, data) {
            switch (action) {
                case 'copy':
                    navigator.clipboard.writeText(data);
                    showStatus('Copied to clipboard!', 'success');
                    break;
                case 'download':
                    downloadConfig(data);
                    break;
                case 'check_extension':
                    showStatus('Check your browser extension for the MCP connection status', 'success');
                    break;
                case 'open_mcp_client':
                    showStatus('Open your MCP client application to see the new connection', 'success');
                    break;
            }
        }

        function downloadConfig(config) {
            const blob = new Blob([JSON.stringify(config, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'mcp-config.json';
            a.click();
            URL.revokeObjectURL(url);
            showStatus('Configuration downloaded!', 'success');
        }

        function showStatus(message, type) {
            const status = document.getElementById('status');
            status.textContent = message;
            status.className = 'status ' + type;
            status.style.display = 'block';
            setTimeout(() => {
                status.style.display = 'none';
            }, 3000);
        }

        // Auto-try deep links
        ${options.deepLinkUrl ? `
        setTimeout(() => {
            window.location.href = '${options.deepLinkUrl}';
        }, 2000);
        ` : ''}
    </script>
</body>
</html>`;
  }

  /**
   * Generate error page
   */
  private showError(res: Response, message: string): void {
    res.status(400).send(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authentication Error - n8n MCP</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            background: white;
            border-radius: 12px;
            padding: 40px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            text-align: center;
        }
        .error-icon {
            font-size: 64px;
            margin-bottom: 20px;
        }
        .title {
            color: #e53e3e;
            font-size: 24px;
            margin-bottom: 10px;
        }
        .message {
            color: #718096;
            font-size: 16px;
            margin-bottom: 30px;
        }
        .btn {
            background: #667eea;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 6px;
            font-size: 16px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
        }
        .btn:hover {
            background: #5a67d8;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="error-icon">❌</div>
        <h1 class="title">Authentication Failed</h1>
        <p class="message">${message}</p>
        <a href="/mcp/connect" class="btn">Try Again</a>
    </div>
</body>
</html>`);
  }

  private detectClientType(userAgent: string, requestedType: string): string {
    if (requestedType !== 'auto') {
      return requestedType;
    }

    const ua = userAgent.toLowerCase();
    
    if (ua.includes('claude') || ua.includes('anthropic')) {
      return 'claude_desktop';
    }
    
    if (ua.includes('windsurf')) {
      return 'windsurf';
    }
    
    if (ua.includes('extension') || ua.includes('chrome-extension')) {
      return 'browser_extension';
    }
    
    return 'manual';
  }

  private buildGoogleAuthUrl(state: string): string {
    const params = new URLSearchParams({
      client_id: this.config.google.clientId,
      redirect_uri: this.config.google.callbackUrl,
      scope: 'openid email profile',
      response_type: 'code',
      state: state
    });

    return `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
  }

  private getBaseUrl(req: Request): string {
    const protocol = req.get('x-forwarded-proto') || req.protocol;
    const host = req.get('x-forwarded-host') || req.get('host');
    return `${protocol}://${host}`;
  }

  private generateSessionId(): string {
    return crypto.randomBytes(16).toString('hex');
  }

  private generateFullConfig(req: Request, session: ConnectionSession): any {
    const baseUrl = this.getBaseUrl(req);
    
    return {
      mcpServers: {
        "n8n-docs": {
          command: "npx",
          args: [
            "-y",
            "mcp-remote", 
            `${baseUrl}/mcp`,
            "--header",
            `Authorization: Bearer ${session.tokens!.accessToken}`
          ]
        }
      },
      user: {
        id: session.user!.id,
        email: session.user!.email,
        name: session.user!.name
      },
      server: {
        url: `${baseUrl}/mcp`,
        version: "2.7.0"
      }
    };
  }
}

interface ConnectionSession {
  id: string;
  clientType: string;
  status: 'pending' | 'authenticated' | 'configured' | 'failed';
  createdAt: Date;
  user: GoogleUser | null;
  tokens: { accessToken: string; refreshToken: string; expiresIn: number } | null;
}
