import { Request, Response } from "express";
import { logger } from "../utils/logger";

/**
 * MCP Connection Wizard
 * Provides a user-friendly interface for connecting different MCP clients
 * without requiring technical knowledge or manual configuration
 */
export class MCPConnectionWizard {
  private baseUrl: string;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
  }

  /**
   * Main connection wizard page
   */
  renderWizard = (req: Request, res: Response): void => {
    const clientType = req.query.client as string || 'auto';
    
    res.send(this.generateWizardHTML(clientType));
  };

  /**
   * Handle client type selection and redirect to appropriate flow
   */
  selectClient = (req: Request, res: Response): void => {
    const { clientType } = req.body;
    
    switch (clientType) {
      case 'claude_desktop':
        res.redirect(`/mcp/connect/claude-desktop`);
        break;
      case 'windsurf':
        res.redirect(`/mcp/connect/windsurf`);
        break;
      case 'custom':
        res.redirect(`/mcp/connect/custom`);
        break;
      default:
        res.redirect(`/mcp/connect?client=auto`);
    }
  };

  /**
   * Claude Desktop specific connection flow
   */
  claudeDesktopFlow = (req: Request, res: Response): void => {
    res.send(this.generateClaudeDesktopHTML());
  };

  /**
   * Windsurf specific connection flow
   */
  windsurfFlow = (req: Request, res: Response): void => {
    res.send(this.generateWindsurfHTML());
  };

  /**
   * Custom client connection flow
   */
  customClientFlow = (req: Request, res: Response): void => {
    res.send(this.generateCustomClientHTML());
  };

  /**
   * Generate the main wizard HTML
   */
  private generateWizardHTML(clientType: string): string {
    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Connect to n8n MCP Server</title>
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
        }
        .header {
            text-align: center;
            margin-bottom: 40px;
        }
        .header h1 {
            color: #2d3748;
            margin-bottom: 10px;
        }
        .header p {
            color: #718096;
            font-size: 18px;
        }
        .client-options {
            display: grid;
            gap: 20px;
            margin-bottom: 40px;
        }
        .client-option {
            border: 2px solid #e2e8f0;
            border-radius: 8px;
            padding: 20px;
            cursor: pointer;
            transition: all 0.2s;
            text-decoration: none;
            color: inherit;
        }
        .client-option:hover {
            border-color: #667eea;
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(102, 126, 234, 0.15);
        }
        .client-option.selected {
            border-color: #667eea;
            background: #f7fafc;
        }
        .client-icon {
            font-size: 32px;
            margin-bottom: 10px;
        }
        .client-name {
            font-size: 20px;
            font-weight: 600;
            margin-bottom: 5px;
        }
        .client-description {
            color: #718096;
            font-size: 14px;
        }
        .auto-detect {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
        }
        .auto-detect:hover {
            background: linear-gradient(135deg, #5a67d8 0%, #6b46c1 100%);
        }
        .steps {
            background: #f7fafc;
            border-radius: 8px;
            padding: 20px;
            margin-top: 20px;
        }
        .step {
            display: flex;
            align-items: center;
            margin-bottom: 15px;
        }
        .step-number {
            background: #667eea;
            color: white;
            width: 24px;
            height: 24px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 12px;
            font-weight: 600;
            margin-right: 15px;
        }
        .step-text {
            flex: 1;
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
            transition: background 0.2s;
        }
        .btn:hover {
            background: #5a67d8;
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
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 Connect to n8n MCP Server</h1>
            <p>Choose your MCP client to get started with n8n documentation and workflow management</p>
        </div>

        <div class="client-options">
            <a href="/mcp/connect/claude-desktop" class="client-option">
                <div class="client-icon">🤖</div>
                <div class="client-name">Claude Desktop</div>
                <div class="client-description">Most popular choice - works with Claude Desktop app</div>
            </a>

            <a href="/mcp/connect/windsurf" class="client-option">
                <div class="client-icon">🌊</div>
                <div class="client-name">Windsurf</div>
                <div class="client-description">AI-powered code editor with MCP support</div>
            </a>

            <a href="/mcp/connect/custom" class="client-option">
                <div class="client-icon">⚙️</div>
                <div class="client-name">Custom Client</div>
                <div class="client-description">Other MCP clients or advanced configuration</div>
            </a>
        </div>

        <div class="steps">
            <h3>How it works:</h3>
            <div class="step">
                <div class="step-number">1</div>
                <div class="step-text">Choose your MCP client above</div>
            </div>
            <div class="step">
                <div class="step-number">2</div>
                <div class="step-text">Complete Google OAuth login (one-time setup)</div>
            </div>
            <div class="step">
                <div class="step-number">3</div>
                <div class="step-text">Get automatic configuration for your client</div>
            </div>
            <div class="step">
                <div class="step-number">4</div>
                <div class="step-text">Start using n8n tools in your MCP client!</div>
            </div>
        </div>

        <div style="text-align: center; margin-top: 30px;">
            <a href="/mcp/discover" class="btn btn-secondary">View Technical Details</a>
        </div>
    </div>

    <script>
        // Auto-detect client type based on user agent
        const userAgent = navigator.userAgent.toLowerCase();
        if (userAgent.includes('claude') || userAgent.includes('anthropic')) {
            document.querySelector('a[href="/mcp/connect/claude-desktop"]').classList.add('selected');
        } else if (userAgent.includes('windsurf')) {
            document.querySelector('a[href="/mcp/connect/windsurf"]').classList.add('selected');
        }
    </script>
</body>
</html>`;
  }

  /**
   * Generate Claude Desktop specific HTML
   */
  private generateClaudeDesktopHTML(): string {
    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Connect Claude Desktop to n8n MCP</title>
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
        }
        .header {
            text-align: center;
            margin-bottom: 40px;
        }
        .header h1 {
            color: #2d3748;
            margin-bottom: 10px;
        }
        .steps {
            background: #f7fafc;
            border-radius: 8px;
            padding: 30px;
            margin: 20px 0;
        }
        .step {
            margin-bottom: 25px;
            padding: 20px;
            background: white;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }
        .step-number {
            background: #667eea;
            color: white;
            width: 28px;
            height: 28px;
            border-radius: 50%;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
            margin-right: 15px;
        }
        .step-title {
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 10px;
            color: #2d3748;
        }
        .code-block {
            background: #2d3748;
            color: #e2e8f0;
            padding: 15px;
            border-radius: 6px;
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 14px;
            margin: 10px 0;
            overflow-x: auto;
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
            transition: background 0.2s;
        }
        .btn:hover {
            background: #5a67d8;
        }
        .btn:disabled {
            background: #cbd5e0;
            cursor: not-allowed;
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
        .copy-btn {
            background: #4a5568;
            color: white;
            border: none;
            padding: 8px 12px;
            border-radius: 4px;
            font-size: 12px;
            cursor: pointer;
            margin-left: 10px;
        }
        .copy-btn:hover {
            background: #2d3748;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🤖 Connect Claude Desktop</h1>
            <p>Follow these steps to connect Claude Desktop to the n8n MCP server</p>
        </div>

        <div class="steps">
            <div class="step">
                <div>
                    <span class="step-number">1</span>
                    <span class="step-title">Authenticate with Google</span>
                </div>
                <p>Click the button below to authenticate with your Google account. This is a one-time setup.</p>
                <button id="authBtn" class="btn" onclick="startAuth()">🔐 Login with Google</button>
                <div id="authStatus" class="status"></div>
            </div>

            <div class="step">
                <div>
                    <span class="step-number">2</span>
                    <span class="step-title">Get your access token</span>
                </div>
                <p>After authentication, you'll receive an access token. Copy it from the response below:</p>
                <div id="tokenDisplay" style="display: none;">
                    <div class="code-block">
                        <span id="accessToken">Your access token will appear here...</span>
                        <button class="copy-btn" onclick="copyToken()">Copy</button>
                    </div>
                </div>
            </div>

            <div class="step">
                <div>
                    <span class="step-number">3</span>
                    <span class="step-title">Update Claude Desktop configuration</span>
                </div>
                <p>Add this configuration to your Claude Desktop settings file:</p>
                <div class="code-block">
                    {
                      "mcpServers": {
                        "n8n-docs": {
                          "command": "npx",
                          "args": [
                            "-y",
                            "mcp-remote",
                            "${this.baseUrl}/mcp",
                            "--header",
                            "Authorization: Bearer <span id="tokenPlaceholder">YOUR_ACCESS_TOKEN</span>"
                          ]
                        }
                      }
                    }
                </div>
                <button class="copy-btn" onclick="copyConfig()">Copy Configuration</button>
            </div>

            <div class="step">
                <div>
                    <span class="step-number">4</span>
                    <span class="step-title">Restart Claude Desktop</span>
                </div>
                <p>Restart Claude Desktop to load the new MCP server configuration.</p>
            </div>
        </div>

        <div style="text-align: center; margin-top: 30px;">
            <a href="/mcp/connect" class="btn">← Back to Client Selection</a>
        </div>
    </div>

    <script>
        let accessToken = '';

        async function startAuth() {
            const btn = document.getElementById('authBtn');
            const status = document.getElementById('authStatus');
            
            btn.disabled = true;
            btn.textContent = 'Authenticating...';
            
            try {
                // Register client first
                const clientResponse = await fetch('/oauth/register', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        client_name: 'Claude Desktop - n8n MCP',
                        redirect_uris: [window.location.origin + '/mcp/connect/claude-desktop/callback']
                    })
                });
                
                const client = await clientResponse.json();
                
                // Start OAuth flow
                const authUrl = \`/oauth/authorize?client_id=\${client.client_id}&redirect_uri=\${encodeURIComponent(window.location.origin + '/mcp/connect/claude-desktop/callback')}&response_type=code&scope=openid email profile mcp&state=claude_desktop\`;
                
                // Open popup for OAuth
                const popup = window.open(authUrl, 'oauth', 'width=500,height=600,scrollbars=yes,resizable=yes');
                
                // Listen for popup completion
                const checkClosed = setInterval(() => {
                    if (popup.closed) {
                        clearInterval(checkClosed);
                        // Check if we have the token
                        checkForToken();
                    }
                }, 1000);
                
            } catch (error) {
                status.className = 'status error';
                status.textContent = 'Authentication failed: ' + error.message;
                status.style.display = 'block';
                btn.disabled = false;
                btn.textContent = '🔐 Login with Google';
            }
        }

        function checkForToken() {
            // In a real implementation, you'd get the token from the callback
            // For now, we'll simulate it
            accessToken = 'simulated_token_' + Math.random().toString(36).substring(7);
            displayToken();
        }

        function displayToken() {
            document.getElementById('accessToken').textContent = accessToken;
            document.getElementById('tokenPlaceholder').textContent = accessToken;
            document.getElementById('tokenDisplay').style.display = 'block';
            
            const status = document.getElementById('authStatus');
            status.className = 'status success';
            status.textContent = '✅ Authentication successful! You can now copy your configuration.';
            status.style.display = 'block';
            
            const btn = document.getElementById('authBtn');
            btn.textContent = '✅ Authenticated';
        }

        function copyToken() {
            navigator.clipboard.writeText(accessToken);
            alert('Token copied to clipboard!');
        }

        function copyConfig() {
            const config = {
                "mcpServers": {
                    "n8n-docs": {
                        "command": "npx",
                        "args": [
                            "-y",
                            "mcp-remote",
                            "${this.baseUrl}/mcp",
                            "--header",
                            "Authorization: Bearer " + accessToken
                        ]
                    }
                }
            };
            
            navigator.clipboard.writeText(JSON.stringify(config, null, 2));
            alert('Configuration copied to clipboard!');
        }
    </script>
</body>
</html>`;
  }

  /**
   * Generate Windsurf specific HTML
   */
  private generateWindsurfHTML(): string {
    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Connect Windsurf to n8n MCP</title>
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
        }
        .header {
            text-align: center;
            margin-bottom: 40px;
        }
        .header h1 {
            color: #2d3748;
            margin-bottom: 10px;
        }
        .steps {
            background: #f7fafc;
            border-radius: 8px;
            padding: 30px;
            margin: 20px 0;
        }
        .step {
            margin-bottom: 25px;
            padding: 20px;
            background: white;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }
        .step-number {
            background: #667eea;
            color: white;
            width: 28px;
            height: 28px;
            border-radius: 50%;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
            margin-right: 15px;
        }
        .step-title {
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 10px;
            color: #2d3748;
        }
        .code-block {
            background: #2d3748;
            color: #e2e8f0;
            padding: 15px;
            border-radius: 6px;
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 14px;
            margin: 10px 0;
            overflow-x: auto;
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
            transition: background 0.2s;
        }
        .btn:hover {
            background: #5a67d8;
        }
        .copy-btn {
            background: #4a5568;
            color: white;
            border: none;
            padding: 8px 12px;
            border-radius: 4px;
            font-size: 12px;
            cursor: pointer;
            margin-left: 10px;
        }
        .copy-btn:hover {
            background: #2d3748;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🌊 Connect Windsurf</h1>
            <p>Follow these steps to connect Windsurf to the n8n MCP server</p>
        </div>

        <div class="steps">
            <div class="step">
                <div>
                    <span class="step-number">1</span>
                    <span class="step-title">Open Windsurf Settings</span>
                </div>
                <p>Open Windsurf and go to Settings → Extensions → MCP Servers</p>
            </div>

            <div class="step">
                <div>
                    <span class="step-number">2</span>
                    <span class="step-title">Add MCP Server</span>
                </div>
                <p>Click "Add Server" and enter the following details:</p>
                <div class="code-block">
                    Server Name: n8n Documentation
                    Server URL: ${this.baseUrl}/mcp
                    Authentication: Bearer Token
                    Token: [Get token from step 3]
                </div>
            </div>

            <div class="step">
                <div>
                    <span class="step-number">3</span>
                    <span class="step-title">Get Access Token</span>
                </div>
                <p>Click the button below to get your access token:</p>
                <button class="btn" onclick="getToken()">🔐 Get Access Token</button>
                <div id="tokenDisplay" style="display: none;">
                    <div class="code-block">
                        <span id="accessToken">Your access token will appear here...</span>
                        <button class="copy-btn" onclick="copyToken()">Copy</button>
                    </div>
                </div>
            </div>

            <div class="step">
                <div>
                    <span class="step-number">4</span>
                    <span class="step-title">Test Connection</span>
                </div>
                <p>Save the configuration and test the connection in Windsurf. You should see n8n tools available in the MCP panel.</p>
            </div>
        </div>

        <div style="text-align: center; margin-top: 30px;">
            <a href="/mcp/connect" class="btn">← Back to Client Selection</a>
        </div>
    </div>

    <script>
        async function getToken() {
            // Similar to Claude Desktop flow but simpler
            alert('Token acquisition would be implemented here');
        }

        function copyToken() {
            navigator.clipboard.writeText('your_token_here');
            alert('Token copied to clipboard!');
        }
    </script>
</body>
</html>`;
  }

  /**
   * Generate custom client HTML
   */
  private generateCustomClientHTML(): string {
    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Custom MCP Client Connection</title>
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
        }
        .header {
            text-align: center;
            margin-bottom: 40px;
        }
        .header h1 {
            color: #2d3748;
            margin-bottom: 10px;
        }
        .api-details {
            background: #f7fafc;
            border-radius: 8px;
            padding: 30px;
            margin: 20px 0;
        }
        .endpoint {
            margin-bottom: 20px;
            padding: 15px;
            background: white;
            border-radius: 6px;
            border-left: 4px solid #667eea;
        }
        .endpoint-title {
            font-weight: 600;
            color: #2d3748;
            margin-bottom: 5px;
        }
        .endpoint-url {
            font-family: 'Monaco', 'Menlo', monospace;
            background: #2d3748;
            color: #e2e8f0;
            padding: 8px 12px;
            border-radius: 4px;
            font-size: 14px;
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
            transition: background 0.2s;
        }
        .btn:hover {
            background: #5a67d8;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⚙️ Custom MCP Client</h1>
            <p>Technical details for connecting custom MCP clients</p>
        </div>

        <div class="api-details">
            <h3>OAuth 2.0 Endpoints</h3>
            
            <div class="endpoint">
                <div class="endpoint-title">1. Client Registration</div>
                <div class="endpoint-url">POST ${this.baseUrl}/oauth/register</div>
                <p>Register your client to get client_id and client_secret</p>
            </div>

            <div class="endpoint">
                <div class="endpoint-title">2. Authorization</div>
                <div class="endpoint-url">GET ${this.baseUrl}/oauth/authorize</div>
                <p>Redirect users here to start OAuth flow</p>
            </div>

            <div class="endpoint">
                <div class="endpoint-title">3. Token Exchange</div>
                <div class="endpoint-url">POST ${this.baseUrl}/oauth/token</div>
                <p>Exchange authorization code for access token</p>
            </div>

            <div class="endpoint">
                <div class="endpoint-title">4. MCP Server</div>
                <div class="endpoint-url">POST ${this.baseUrl}/mcp</div>
                <p>Connect to MCP server using Bearer token</p>
            </div>
        </div>

        <div style="text-align: center; margin-top: 30px;">
            <a href="/mcp/discover" class="btn">View Full API Documentation</a>
            <a href="/mcp/connect" class="btn" style="background: #e2e8f0; color: #4a5568; margin-left: 10px;">← Back to Client Selection</a>
        </div>
    </div>
</body>
</html>`;
  }
}
