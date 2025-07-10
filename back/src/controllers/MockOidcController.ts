import { Request, Response } from 'express';
import crypto from 'crypto';
import { mockUsers, MockUser } from '../config/mock-auth';
import { OIDC_TEST_SCENARIOS, OidcTestRunner } from './OidcTestScenarios';

export class MockOidcController {
  private readonly MOCK_CLIENT_ID = 'mock-client';
  private readonly MOCK_CLIENT_SECRET = 'mock-secret-123'; // For testing Basic Auth

  // Dynamic issuer based on request context
  private getIssuer(req: Request): string {
    const protocol = req.headers['x-forwarded-proto'] || req.protocol || 'http';
    const host = req.headers['x-forwarded-host'] || req.get('host') || 'localhost:5000';
    return `${protocol}://${host}/api/mock-oidc`;
  }

  // Get issuer for callback (should match what client expects)
  private getCallbackIssuer(req: Request): string {
    // For development with mock OIDC, use the internal issuer that matches client configuration
    const useMockOIDC = process.env.NODE_ENV === 'development' && process.env.USE_MOCK_OIDC === 'true';

    if (useMockOIDC) {
      // Return the internal issuer that matches what the client was configured with
      return process.env.MOCK_OIDC_INTERNAL_ISSUER || 'http://localhost:5000/api/mock-oidc';
    }

    // For production, use the dynamic issuer
    return this.getIssuer(req);
  }

  // Generate a consistent RSA key pair for JWT signing (in production, use proper key management)
  private readonly keyPair = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });

  // In-memory storage for authorization codes and refresh tokens
  private authorizationCodes = new Map<string, {
    code: string;
    client_id: string;
    redirect_uri: string;
    user: MockUser;
    scope: string;
    nonce?: string;
    code_challenge?: string;
    code_challenge_method?: string;
    expires_at: number;
    used: boolean;
  }>();

  private refreshTokens = new Map<string, {
    token: string;
    user: MockUser;
    scope: string;
    expires_at: number;
    used: boolean;
  }>();

  // Map access tokens to users for userinfo endpoint
  private accessTokens = new Map<string, {
    token: string;
    user: MockUser;
    expires_at: number;
  }>();

  // Valid redirect URIs (in production, these would be registered with the client)
  private readonly VALID_REDIRECT_URIS = [
    'https://node.localhost/api/auth/callback',
    process.env.OIDC_CALLBACK_URL || 'https://node.localhost/api/auth/callback'
  ].filter((uri, index, array) => array.indexOf(uri) === index); // Remove duplicates

  // Helper functions for OIDC validations
  private validateClientId = (client_id: string): boolean => {
    return client_id === this.MOCK_CLIENT_ID;
  };

  private validateRedirectUri = (redirect_uri: string): boolean => {
    return this.VALID_REDIRECT_URIS.includes(redirect_uri);
  };

  private validateScope = (scope: string): boolean => {
    const validScopes = ['openid', 'profile', 'email', 'offline_access'];
    const requestedScopes = scope.split(' ');
    return requestedScopes.every(s => validScopes.includes(s)) && requestedScopes.includes('openid');
  };

  private validateResponseType = (response_type: string): boolean => {
    return response_type === 'code';
  };

  private generateSecureToken = (length: number = 32): string => {
    return crypto.randomBytes(length).toString('base64url');
  };

  // Generate a proper JWT token
  private generateJWT = (payload: Record<string, any>, expiresInMinutes?: number): string => {
    const header = {
      alg: 'RS256',
      typ: 'JWT',
      kid: 'mock-key-1'
    };

    // Use provided expiry, environment variable, or default to 60 minutes
    const expiryMinutes = expiresInMinutes ?? parseInt(process.env.MOCK_OIDC_JWT_EXPIRY_MINUTES || '60');
    const expiresInSeconds = expiryMinutes * 60; // Convert minutes to seconds

    console.log(`🔐 Generating JWT with expiry: ${expiryMinutes} minutes (${expiresInSeconds} seconds)`);

    const now = Math.floor(Date.now() / 1000);
    const jwtPayload = {
      ...payload,
      iat: now,
      exp: now + expiresInSeconds
    };

    const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
    const encodedPayload = Buffer.from(JSON.stringify(jwtPayload)).toString('base64url');
    const data = `${encodedHeader}.${encodedPayload}`;

    // Create signature using crypto.sign
    const sign = crypto.createSign('RSA-SHA256');
    sign.update(data);
    const signature = sign.sign(this.keyPair.privateKey, 'base64url');

    return `${data}.${signature}`;
  };

  // JWKS endpoint for JWT verification
  public jwks = (req: Request, res: Response): void => {
    try {
      const jwk = crypto.createPublicKey(this.keyPair.publicKey).export({ format: 'jwk' });

      res.json({
        keys: [{
          ...jwk,
          alg: 'RS256',
          use: 'sig',
          kid: 'mock-key-1'
        }]
      });
    } catch (error) {
      console.error('Error generating JWKS:', error);
      res.status(500).json({ error: 'internal_server_error' });
    }
  };

  // Mock OIDC Discovery endpoint with test client info
  public discovery = (req: Request, res: Response): void => {
    try {
      console.log('🔍 Discovery endpoint called!');
      console.log('Headers:', req.headers);
      console.log('Protocol:', req.protocol);
      console.log('Host:', req.get('host'));

      const protocol = req.headers['x-forwarded-proto'] || req.protocol;
      const host = req.headers['x-forwarded-host'] || req.get('host');
      const baseUrl = `${protocol}://${host}/api/mock-oidc`;

      console.log('Base URL:', baseUrl);

    res.json({
      issuer: baseUrl,
      authorization_endpoint: `${baseUrl}/auth`,
      token_endpoint: `${baseUrl}/token`,
      userinfo_endpoint: `${baseUrl}/userinfo`,
      jwks_uri: `${baseUrl}/.well-known/jwks.json`,
      response_types_supported: ['code'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256'],
      scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
      claims_supported: ['sub', 'email', 'given_name', 'family_name', 'name'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      // Test client credentials for development
      test_client_id: this.MOCK_CLIENT_ID,
      test_client_secret: this.MOCK_CLIENT_SECRET,
      test_basic_auth: Buffer.from(`${this.MOCK_CLIENT_ID}:${this.MOCK_CLIENT_SECRET}`).toString('base64')
    });
    } catch (error) {
      console.error('❌ Error in discovery endpoint:', error);
      res.status(500).json({ error: 'Internal server error', message: 'Discovery endpoint failed' });
    }
  };

  // Enhanced authorization endpoint with comprehensive validations
  public authorize = (req: Request, res: Response): void => {
    const {
      client_id,
      redirect_uri,
      response_type,
      scope,
      state,
      nonce,
      acr_values,
      code_challenge,
      code_challenge_method
    } = req.query;

    console.log('🎭 Mock OIDC Authorization Request with Enhanced Validation:', {
      client_id, redirect_uri, response_type, scope, state, nonce, acr_values,
      code_challenge: code_challenge ? 'present' : 'none', code_challenge_method,
      timestamp: new Date().toISOString(),
      userAgent: req.get('User-Agent'),
      origin: req.get('Origin')
    });

    // ====== COMPREHENSIVE OIDC VALIDATIONS ======

    // Security: Sanitize parameters to prevent XSS
    const sanitizedState = state ? String(state).replace(/[<>&"']/g, '') : undefined;
    const sanitizedNonce = nonce ? String(nonce).replace(/[<>&"']/g, '') : undefined;

    // 1. Validate client_id
    if (!client_id || !this.validateClientId(client_id as string)) {
      console.error('❌ OIDC Validation Failed: Invalid client_id', {
        provided: client_id,
        expected: this.MOCK_CLIENT_ID,
        timestamp: new Date().toISOString()
      });
      res.status(400).send('❌ Invalid client_id. Expected: ' + this.MOCK_CLIENT_ID);
      return;
    }

    // 2. Validate redirect_uri against whitelist
    if (!redirect_uri || !this.validateRedirectUri(redirect_uri as string)) {
      console.error('❌ OIDC Validation Failed: Invalid redirect_uri', {
        provided: redirect_uri,
        whitelist: this.VALID_REDIRECT_URIS,
        timestamp: new Date().toISOString()
      });
      res.status(400).send('❌ Invalid redirect_uri. Must be whitelisted: ' + this.VALID_REDIRECT_URIS.join(', '));
      return;
    }

    // 3. Validate response_type
    if (!response_type || !this.validateResponseType(response_type as string)) {
      console.error('❌ OIDC Validation Failed: Invalid response_type', {
        provided: response_type,
        supported: ['code'],
        timestamp: new Date().toISOString()
      });
      const errorUrl = new URL(redirect_uri as string);
      errorUrl.searchParams.set('error', 'unsupported_response_type');
      errorUrl.searchParams.set('error_description', 'Only authorization code flow is supported');
      if (sanitizedState) errorUrl.searchParams.set('state', sanitizedState);
      res.redirect(errorUrl.toString());
      return;
    }

    // 4. Validate scope (must include 'openid')
    if (!scope || !this.validateScope(scope as string)) {
      console.error('❌ OIDC Validation Failed: Invalid scope', {
        provided: scope,
        requirement: 'Must include openid',
        timestamp: new Date().toISOString()
      });
      const errorUrl = new URL(redirect_uri as string);
      errorUrl.searchParams.set('error', 'invalid_scope');
      errorUrl.searchParams.set('error_description', 'Scope must include openid');
      if (sanitizedState) errorUrl.searchParams.set('state', sanitizedState);
      res.redirect(errorUrl.toString());
      return;
    }

    // 5. Validate PKCE if present
    if (code_challenge) {
      if (!code_challenge_method || code_challenge_method !== 'S256') {
        console.error('❌ OIDC Validation Failed: Invalid PKCE method', {
          provided: code_challenge_method,
          required: 'S256',
          timestamp: new Date().toISOString()
        });
        const errorUrl = new URL(redirect_uri as string);
        errorUrl.searchParams.set('error', 'invalid_request');
        errorUrl.searchParams.set('error_description', 'PKCE requires S256 method');
        if (sanitizedState) errorUrl.searchParams.set('state', sanitizedState);
        res.redirect(errorUrl.toString());
        return;
      }
      if ((code_challenge as string).length < 43) {
        console.error('❌ OIDC Validation Failed: Invalid PKCE challenge length', {
          provided: (code_challenge as string).length,
          minimum: 43,
          timestamp: new Date().toISOString()
        });
        const errorUrl = new URL(redirect_uri as string);
        errorUrl.searchParams.set('error', 'invalid_request');
        errorUrl.searchParams.set('error_description', 'Invalid PKCE code challenge length');
        if (sanitizedState) errorUrl.searchParams.set('state', sanitizedState);
        res.redirect(errorUrl.toString());
        return;
      }
    }

    // 6. Security checks with warnings
    const securityWarnings = [];
    if (!state) {
      securityWarnings.push('No state parameter - CSRF vulnerability!');
    }
    if (!nonce) {
      securityWarnings.push('No nonce parameter - replay attack vulnerability!');
    }
    if (!code_challenge) {
      securityWarnings.push('No PKCE code challenge - authorization code interception vulnerability!');
    }

    if (securityWarnings.length > 0) {
      console.warn('⚠️  Security warnings for OIDC request:', {
        warnings: securityWarnings,
        client_id,
        redirect_uri,
        timestamp: new Date().toISOString()
      });
    }

    // 7. Check for potential malicious patterns
    const maliciousPatterns = [
      /script[^>]*>/i,
      /javascript:/i,
      /vbscript:/i,
      /on\w+\s*=/i,
      /drop\s+table/i,
      /union\s+select/i,
      /insert\s+into/i,
      /delete\s+from/i
    ];

    const allParams = { client_id, redirect_uri, response_type, scope, state, nonce };
    Object.entries(allParams).forEach(([key, value]) => {
      if (value && typeof value === 'string') {
        maliciousPatterns.forEach(pattern => {
          if (pattern.test(value)) {
            console.error('🚨 SECURITY ALERT: Malicious pattern detected', {
              parameter: key,
              value,
              pattern: pattern.toString(),
              timestamp: new Date().toISOString(),
              userAgent: req.get('User-Agent'),
              ip: req.ip
            });
          }
        });
      }
    });

    console.log('✅ All OIDC validations passed', {
      client_id,
      redirect_uri,
      has_pkce: !!code_challenge,
      security_warnings: securityWarnings.length,
      timestamp: new Date().toISOString()
    });

    // Enhanced login form showing validation results
    const loginForm = `
      <!DOCTYPE html>
      <html>
      <head>
          <title>🔐 Production-Grade Mock OIDC Provider</title>
          <style>
              body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 700px; margin: 50px auto; padding: 20px; background: #f8f9fa; }
              .container { background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
              .validation { background: linear-gradient(135deg, #e7f3ff 0%, #f0f9ff 100%); padding: 20px; margin: 20px 0; border-radius: 8px; border-left: 4px solid #007bff; }
              .security { background: linear-gradient(135deg, #f0f9ff 0%, #e6fffa 100%); padding: 20px; margin: 20px 0; border-radius: 8px; border-left: 4px solid #28a745; }
              .warning { background: linear-gradient(135deg, #fff3cd 0%, #ffeeba 100%); padding: 15px; margin: 15px 0; border-radius: 8px; border-left: 4px solid #ffc107; }
              .param { font-family: 'Monaco', 'Consolas', monospace; background: #f1f3f4; padding: 4px 8px; border-radius: 4px; font-size: 0.9em; }
              .form-group { margin: 20px 0; }
              label { display: block; margin-bottom: 8px; font-weight: 600; color: #495057; }
              select, button { width: 100%; padding: 15px; border: 2px solid #e9ecef; border-radius: 8px; font-size: 16px; }
              button { background: linear-gradient(135deg, #007bff 0%, #0056b3 100%); color: white; border: none; cursor: pointer; margin-top: 20px; font-weight: 600; transition: all 0.2s; }
              button:hover { transform: translateY(-1px); box-shadow: 0 4px 8px rgba(0,123,255,0.3); }
              .user-info { background: #f8f9fa; padding: 15px; margin: 12px 0; border-radius: 6px; border-left: 3px solid #6c757d; }
              h2 { color: #212529; text-align: center; margin-bottom: 30px; font-size: 2em; }
              h3 { color: #495057; margin-bottom: 15px; font-size: 1.3em; }
              .check { color: #28a745; font-weight: bold; }
              .warn { color: #ffc107; font-weight: bold; }
              .error { color: #dc3545; font-weight: bold; }
              ul { margin: 10px 0; padding-left: 20px; }
              li { margin: 8px 0; }
              .feature-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 15px 0; }
              .feature { background: #f8f9fa; padding: 12px; border-radius: 6px; text-align: center; }
              .credentials { background: linear-gradient(135deg, #e8f5e8 0%, #f0fff0 100%); padding: 20px; margin: 20px 0; border-radius: 8px; border-left: 4px solid #28a745; }
              .code { font-family: 'Monaco', 'Consolas', monospace; background: #f8f9fa; padding: 8px 12px; border-radius: 4px; font-size: 0.9em; margin: 8px 0; display: block; }
          </style>
      </head>
      <body>
          <div class="container">
              <h2>🔐 Production-Grade Mock OIDC Provider</h2>

              <div class="credentials">
                  <h3>🔑 Test Client Credentials</h3>
                  <p><strong>Client ID:</strong> <code class="code">${this.MOCK_CLIENT_ID}</code></p>
                  <p><strong>Client Secret:</strong> <code class="code">${this.MOCK_CLIENT_SECRET}</code></p>
                  <p><strong>Basic Auth Header:</strong> <code class="code">Basic ${Buffer.from(`${this.MOCK_CLIENT_ID}:${this.MOCK_CLIENT_SECRET}`).toString('base64')}</code></p>
                  <p><em>Use these credentials for testing Basic Authentication in token requests.</em></p>
              </div>

              <div class="validation">
                  <h3>✅ Enhanced Callback Parameters</h3>
                  <p>This provider will return the following parameters in the callback:</p>
                  <ul>
                      <li><strong>code:</strong> Authorization code (standard)</li>
                      <li><strong>state:</strong> CSRF protection state (standard)</li>
                      <li><strong>scope:</strong> Granted scope (additional)</li>
                      <li><strong>iss:</strong> Issuer URL (additional)</li>
                      <li><strong>client_id:</strong> Client identifier (additional)</li>
                  </ul>
                  <p>These additional parameters will test if your OIDC client properly validates callback parameters.</p>
              </div>

              <div class="validation">
                  <h3>✅ OIDC Security Validation Results</h3>
                  <p><strong>Client ID:</strong> <span class="param">${client_id}</span> <span class="check">✅ Verified</span></p>
                  <p><strong>Redirect URI:</strong> <span class="param">${redirect_uri}</span> <span class="check">✅ Whitelisted</span></p>
                  <p><strong>Response Type:</strong> <span class="param">${response_type}</span> <span class="check">✅ Authorization Code Flow</span></p>
                  <p><strong>Scope:</strong> <span class="param">${scope}</span> <span class="check">✅ Valid (includes openid)</span></p>
                  <p><strong>State:</strong> <span class="param">${sanitizedState || 'None'}</span> ${sanitizedState ? '<span class="check">✅ CSRF Protection</span>' : '<span class="warn">⚠️ Missing (CSRF Risk)</span>'}</p>
                  <p><strong>Nonce:</strong> <span class="param">${sanitizedNonce || 'None'}</span> ${sanitizedNonce ? '<span class="check">✅ Replay Protection</span>' : '<span class="warn">⚠️ Missing (Replay Risk)</span>'}</p>
                  ${code_challenge ? `<p><strong>PKCE:</strong> Challenge with ${code_challenge_method} <span class="check">✅ Enhanced Security</span></p>` : '<p><strong>PKCE:</strong> Not used <span class="warn">⚠️ Recommended for public clients</span></p>'}
                  ${acr_values ? `<p><strong>ACR Values:</strong> <span class="param">${acr_values}</span> <span class="check">✅ Authentication Context</span></p>` : ''}
              </div>

              ${!sanitizedState || !sanitizedNonce ? '<div class="warning"><strong>⚠️ Security Recommendations:</strong><ul>' +
                (!sanitizedState ? '<li>Add state parameter for CSRF protection</li>' : '') +
                (!sanitizedNonce ? '<li>Add nonce parameter for replay protection</li>' : '') +
                '</ul></div>' : ''}

              <div class="security">
                  <h3>🛡️ Security Features Implemented</h3>
                  <div class="feature-grid">
                      <div class="feature">✅ Client ID Verification</div>
                      <div class="feature">✅ Redirect URI Whitelist</div>
                      <div class="feature">✅ Scope Validation</div>
                      <div class="feature">${code_challenge ? '✅' : '➖'} PKCE Code Challenge</div>
                      <div class="feature">${sanitizedState ? '✅' : '⚠️'} State Parameter</div>
                      <div class="feature">${sanitizedNonce ? '✅' : '⚠️'} Nonce Parameter</div>
                      <div class="feature">✅ JWT with RS256</div>
                      <div class="feature">✅ JWKS Endpoint</div>
                      <div class="feature">✅ Single-Use Codes</div>
                      <div class="feature">✅ Code Expiration</div>
                      <div class="feature">✅ Refresh Tokens</div>
                      <div class="feature">✅ OpenID Discovery</div>
                  </div>
              </div>

              <form method="POST" action="/api/mock-oidc/auth">
                  <input type="hidden" name="client_id" value="${client_id}" />
                  <input type="hidden" name="redirect_uri" value="${redirect_uri}" />
                  <input type="hidden" name="response_type" value="${response_type}" />
                  <input type="hidden" name="scope" value="${scope}" />
                  ${sanitizedState ? `<input type="hidden" name="state" value="${sanitizedState}" />` : ''}
                  ${sanitizedNonce ? `<input type="hidden" name="nonce" value="${sanitizedNonce}" />` : ''}
                  ${acr_values ? `<input type="hidden" name="acr_values" value="${acr_values}" />` : ''}
                  ${code_challenge ? `<input type="hidden" name="code_challenge" value="${code_challenge}" />` : ''}
                  ${code_challenge_method ? `<input type="hidden" name="code_challenge_method" value="${code_challenge_method}" />` : ''}

                  <div class="form-group">
                      <label for="user">🧑‍💼 Select Mock User for Authentication:</label>
                      <select name="email" id="user" required>
                          <option value="">-- Choose a user to authenticate --</option>
                          ${mockUsers.map((user: MockUser) => `
                              <option value="${user.email}">
                                  ${user.firstName} ${user.lastName} (${user.role}) - ${user.email}
                              </option>
                          `).join('')}
                      </select>
                  </div>

                  <button type="submit">🔐 Authenticate & Generate Authorization Code</button>
              </form>

              <h3>📋 Available Mock Users</h3>
              ${mockUsers.map((user: MockUser) => `
                  <div class="user-info">
                      <strong>${user.firstName} ${user.lastName}</strong><br>
                      Email: <span class="param">${user.email}</span><br>
                      Role: <span class="param">${user.role}</span><br>
                      Subject: <span class="param">${user.sub}</span>
                  </div>
              `).join('')}
          </div>
      </body>
      </html>
    `;

    res.send(loginForm);
  };

  // Enhanced POST handler with validations
  public handleAuth = (req: Request, res: Response): void => {
    const {
      client_id, redirect_uri, response_type, scope, state, nonce,
      email, acr_values, code_challenge, code_challenge_method
    } = req.body;

    // Re-validate all parameters
    if (!this.validateClientId(client_id) || !this.validateRedirectUri(redirect_uri) ||
        !this.validateResponseType(response_type) || !this.validateScope(scope)) {
      res.status(400).send('❌ Invalid request parameters');
      return;
    }

    if (!email) {
      const errorUrl = new URL(redirect_uri);
      errorUrl.searchParams.set('error', 'invalid_request');
      errorUrl.searchParams.set('error_description', 'User selection required');
      if (state) errorUrl.searchParams.set('state', state);
      res.redirect(errorUrl.toString());
      return;
    }

    const mockUser = mockUsers.find((u: MockUser) => u.email === email);
    if (!mockUser) {
      const errorUrl = new URL(redirect_uri);
      errorUrl.searchParams.set('error', 'access_denied');
      errorUrl.searchParams.set('error_description', 'Invalid user');
      if (state) errorUrl.searchParams.set('state', state);
      res.redirect(errorUrl.toString());
      return;
    }

    // Generate secure authorization code
    const authCode = this.generateSecureToken();
    const expiresAt = Date.now() + (10 * 60 * 1000); // 10 minutes

    // Store with security context and enhanced logging
    this.authorizationCodes.set(authCode, {
      code: authCode,
      client_id,
      redirect_uri,
      user: mockUser,
      scope,
      nonce,
      code_challenge,
      code_challenge_method,
      expires_at: expiresAt,
      used: false
    });

    console.log('✅ Secure authorization code generated:', authCode.substring(0, 8) + '...');
    console.log('🔧 Stored authorization data:', {
      client_id,
      user: mockUser.email,
      scope,
      nonce: nonce ? 'present' : 'missing',
      pkce: code_challenge ? 'present' : 'missing'
    });

    // Build enhanced callback URL with additional parameters for security testing
    const redirectUrl = new URL(redirect_uri);

    // Standard OIDC parameters
    redirectUrl.searchParams.set('code', authCode);
    if (state) redirectUrl.searchParams.set('state', state);

    // Enhanced parameters - disabled by default for compatibility with strict OIDC clients
    // Set OIDC_INCLUDE_ENHANCED_CALLBACK_PARAMS=true to enable for testing
    const includeEnhancedParams = process.env.MOCK_OIDC_INCLUDE_ENHANCED_CALLBACK_PARAMS === 'true';

    if (includeEnhancedParams) {
      // Only add enhanced parameters if explicitly enabled
      // Note: These additional parameters might cause issues with strict OIDC clients
      console.log('🔧 Adding enhanced callback parameters for testing');
      redirectUrl.searchParams.set('scope', scope);

      // For the iss parameter, use the issuer that matches client expectations
      const callbackIssuer = this.getCallbackIssuer(req);
      redirectUrl.searchParams.set('iss', callbackIssuer);
      redirectUrl.searchParams.set('client_id', client_id);

      console.log('🔧 Enhanced callback issuer:', callbackIssuer);
    } else {
      console.log('🔧 Using standard OIDC callback (enhanced parameters disabled)');
    }

    console.log('🔧 Enhanced callback URL with additional parameters:', redirectUrl.toString());
    console.log('📋 Callback parameters:', {
      code: authCode.substring(0, 8) + '...',
      state: state || 'none',
      scope: scope,
      iss: this.getIssuer(req),
      client_id: client_id
    });

    res.redirect(redirectUrl.toString());
  };

  // Enhanced token endpoint with Basic Authentication support
  public token = (req: Request, res: Response): void => {
    const { grant_type, code, client_id, redirect_uri, code_verifier, refresh_token } = req.body;

    console.log('🎭 Token Request with Enhanced Validation:');
    console.log('Headers:', {
      'content-type': req.headers['content-type'],
      'authorization': req.headers.authorization ? 'Basic [REDACTED]' : 'none'
    });
    console.log('Full request body:', req.body);

    // Extract client credentials from Basic Auth header or body
    let authClientId = client_id;
    let clientSecret = '';

    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Basic ')) {
      try {
        const base64Credentials = authHeader.substring(6);
        const credentials = Buffer.from(base64Credentials, 'base64').toString('utf8');
        const [id, secret] = credentials.split(':');
        authClientId = id || '';
        clientSecret = secret || '';
        console.log('🔑 Basic Auth detected - client_id:', authClientId, 'secret:', secret ? 'present' : 'missing');
      } catch (error) {
        console.error('❌ Failed to parse Basic Auth header:', error);
        res.status(401).json({
          error: 'invalid_client',
          error_description: 'Invalid Basic Auth format'
        });
        return;
      }
    } else {
      console.log('📋 Using client credentials from request body');
    }

    console.log('🔍 Validation details:', {
      grant_type,
      code: code ? code.substring(0, 8) + '...' : 'none',
      authClientId,
      redirect_uri,
      code_verifier: code_verifier ? 'present' : 'none',
      refresh_token: refresh_token ? 'present' : 'none',
      clientSecret: clientSecret ? 'present' : 'none'
    });

    // Validate client credentials
    if (!authClientId || authClientId !== this.MOCK_CLIENT_ID) {
      console.log('❌ Invalid client_id:', authClientId, 'expected:', this.MOCK_CLIENT_ID);
      res.status(401).json({
        error: 'invalid_client',
        error_description: 'Invalid client_id',
        received: authClientId,
        expected: this.MOCK_CLIENT_ID
      });
      return;
    }

    // For testing: validate client secret if Basic Auth is used
    if (authHeader && authHeader.startsWith('Basic ')) {
      if (!clientSecret || clientSecret !== this.MOCK_CLIENT_SECRET) {
        console.log('❌ Invalid client secret. Expected:', this.MOCK_CLIENT_SECRET, 'Received:', clientSecret);
        res.status(401).json({
          error: 'invalid_client',
          error_description: 'Invalid client secret',
          hint: 'Use Basic Auth with correct credentials'
        });
        return;
      }
      console.log('✅ Client secret validation passed');
    }

    // Handle refresh token flow
    if (grant_type === 'refresh_token') {
      if (!refresh_token) {
        res.status(400).json({ error: 'invalid_request', error_description: 'Refresh token required' });
        return;
      }

      const tokenData = this.refreshTokens.get(refresh_token);
      if (!tokenData || tokenData.used || Date.now() > tokenData.expires_at) {
        res.status(400).json({ error: 'invalid_grant', error_description: 'Invalid or expired refresh token' });
        return;
      }

      // Generate new tokens
      const newAccessToken = this.generateSecureToken();
      const newRefreshToken = this.generateSecureToken();

      // Store new access token mapping
      this.accessTokens.set(newAccessToken, {
        token: newAccessToken,
        user: tokenData.user,
        expires_at: Date.now() + (3600 * 1000) // 1 hour
      });

      // Create new ID token
      const idTokenPayload = {
        iss: this.getIssuer(req),
        sub: tokenData.user.sub,
        aud: client_id,
        email: tokenData.user.email,
        given_name: tokenData.user.firstName,
        family_name: tokenData.user.lastName,
        name: `${tokenData.user.firstName} ${tokenData.user.lastName}`
      };

      const idToken = this.generateJWT(idTokenPayload);

      // Mark old refresh token as used and store new one
      tokenData.used = true;
      this.refreshTokens.set(newRefreshToken, {
        token: newRefreshToken,
        user: tokenData.user,
        scope: tokenData.scope,
        expires_at: Date.now() + (7 * 24 * 60 * 60 * 1000), // 7 days
        used: false
      });

      res.json({
        access_token: newAccessToken,
        token_type: 'Bearer',
        expires_in: 3600,
        id_token: idToken,
        refresh_token: newRefreshToken,
        scope: tokenData.scope
      });
      return;
    }

    // Handle authorization code flow
    if (grant_type !== 'authorization_code') {
      res.status(400).json({ error: 'unsupported_grant_type' });
      return;
    }

    if (!code) {
      res.status(400).json({ error: 'invalid_request', error_description: 'Code required' });
      return;
    }

    const codeData = this.authorizationCodes.get(code);
    if (!codeData) {
      res.status(400).json({ error: 'invalid_grant', error_description: 'Invalid code' });
      return;
    }

    console.log('🎭 Stored code data:', {
      client_id: codeData.client_id,
      redirect_uri: codeData.redirect_uri,
      user: codeData.user.email,
      scope: codeData.scope
    });

    // Enhanced validation logging
    console.log('🔍 Parameter validation:');
    console.log('  Request vs stored client_id:', authClientId, 'vs', codeData.client_id);
    console.log('  Request vs stored redirect_uri:', redirect_uri, 'vs', codeData.redirect_uri);
    console.log('  Grant type:', grant_type);
    console.log('  Code verifier present:', !!code_verifier);
    console.log('  PKCE challenge stored:', !!codeData.code_challenge);

    // Check expiry
    if (Date.now() > codeData.expires_at) {
      this.authorizationCodes.delete(code);
      res.status(400).json({ error: 'invalid_grant', error_description: 'Code expired' });
      return;
    }

    // Check single-use
    if (codeData.used) {
      this.authorizationCodes.delete(code);
      res.status(400).json({ error: 'invalid_grant', error_description: 'Code already used' });
      return;
    }

    // Validate parameters match (be flexible with HTTP/HTTPS for redirect_uri in development)
    const requestRedirectUri = redirect_uri;
    const storedRedirectUri = codeData.redirect_uri;

    // Allow HTTP/HTTPS mismatch in development (containerized environments)
    const uriMatch = requestRedirectUri === storedRedirectUri ||
                     (process.env.NODE_ENV === 'development' &&
                      requestRedirectUri?.replace(/^https?:/, '') === storedRedirectUri?.replace(/^https?:/, ''));

    if (codeData.client_id !== authClientId || !uriMatch) {
      console.log('❌ Parameter validation failed:');
      console.log('  client_id match:', codeData.client_id === authClientId);
      console.log('  redirect_uri match:', uriMatch);
      res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Parameter mismatch',
        details: {
          client_id_match: codeData.client_id === authClientId,
          redirect_uri_match: uriMatch,
          expected_client_id: codeData.client_id,
          received_client_id: authClientId,
          expected_redirect_uri: codeData.redirect_uri,
          received_redirect_uri: redirect_uri
        }
      });
      return;
    }

    console.log('✅ Parameter validation passed');

    // PKCE validation
    if (codeData.code_challenge) {
      if (!code_verifier) {
        res.status(400).json({ error: 'invalid_request', error_description: 'Code verifier required' });
        return;
      }

      const hash = crypto.createHash('sha256').update(code_verifier).digest();
      const challenge = hash.toString('base64url');

      if (challenge !== codeData.code_challenge) {
        res.status(400).json({ error: 'invalid_grant', error_description: 'Invalid code verifier' });
        return;
      }
      console.log('✅ PKCE validation successful');
    }

    // Mark as used
    codeData.used = true;

    // Generate tokens
    const accessToken = this.generateSecureToken();
    const refreshToken = this.generateSecureToken();

    // Store access token mapping for userinfo endpoint
    this.accessTokens.set(accessToken, {
      token: accessToken,
      user: codeData.user,
      expires_at: Date.now() + (3600 * 1000) // 1 hour
    });

    console.log('🎭 Generated access token:', accessToken.substring(0, 8) + '...');
    console.log('🎭 Associated user sub:', codeData.user.sub);

    // Generate proper JWT ID token with all required claims
    const idTokenPayload = {
      iss: this.getCallbackIssuer(req), // Use consistent issuer that matches client expectations
      sub: codeData.user.sub,
      aud: authClientId, // Use validated client_id
      email: codeData.user.email,
      email_verified: true, // Add email_verified claim
      given_name: codeData.user.firstName,
      family_name: codeData.user.lastName,
      name: `${codeData.user.firstName} ${codeData.user.lastName}`,
      // Include nonce if it was provided in the authorization request (required by openid-client)
      ...(codeData.nonce && { nonce: codeData.nonce })
    };

    console.log('🔧 ID Token payload:', {
      ...idTokenPayload,
      nonce: codeData.nonce ? 'present' : 'missing'
    });

    const idToken = this.generateJWT(idTokenPayload);

    // Store refresh token if offline_access is requested
    if (codeData.scope.includes('offline_access')) {
      this.refreshTokens.set(refreshToken, {
        token: refreshToken,
        user: codeData.user,
        scope: codeData.scope,
        expires_at: Date.now() + (7 * 24 * 60 * 60 * 1000), // 7 days
        used: false
      });
    }

    console.log('✅ JWT tokens generated with RS256 signature');
    console.log('✅ All validations passed - returning tokens');

    res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 3600,
      id_token: idToken,
      ...(codeData.scope.includes('offline_access') && { refresh_token: refreshToken }),
      scope: codeData.scope
    });

    // Cleanup
    setTimeout(() => this.authorizationCodes.delete(code), 5000);
  };

  // Mock userinfo endpoint with proper token validation
  public userinfo = (req: Request, res: Response): void => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({
        error: 'invalid_token',
        error_description: 'Bearer token required'
      });
      return;
    }

    const token = authHeader.substring(7);

    // Look up the access token to find the associated user
    const tokenData = this.accessTokens.get(token);
    console.log('🎭 Userinfo request for token:', token.substring(0, 8) + '...');
    console.log('🎭 Token data found:', tokenData ? 'yes' : 'no');
    if (tokenData) {
      console.log('🎭 User sub from token data:', tokenData.user.sub);
    }

    if (!tokenData) {
      res.status(401).json({
        error: 'invalid_token',
        error_description: 'Invalid access token'
      });
      return;
    }

    // Check if token is expired
    if (Date.now() > tokenData.expires_at) {
      this.accessTokens.delete(token);
      res.status(401).json({
        error: 'invalid_token',
        error_description: 'Access token expired'
      });
      return;
    }

    // Return user info for the associated user
    res.json({
      sub: tokenData.user.sub,
      email: tokenData.user.email,
      email_verified: true,
      given_name: tokenData.user.firstName,
      family_name: tokenData.user.lastName,
      name: `${tokenData.user.firstName} ${tokenData.user.lastName}`,
      picture: 'https://via.placeholder.com/155',
      updated_at: Math.floor(Date.now() / 1000)
    });
  };

  // Token introspection endpoint (RFC 7662)
  public introspect = (req: Request, res: Response): void => {
    const { token } = req.body;

    if (!token) {
      res.status(400).json({
        error: 'invalid_request',
        error_description: 'Token parameter required'
      });
      return;
    }

    // Look up the access token
    const tokenData = this.accessTokens.get(token);
    if (!tokenData || Date.now() > tokenData.expires_at) {
      res.json({
        active: false
      });
      return;
    }

    // Return active token info
    res.json({
      active: true,
      client_id: this.MOCK_CLIENT_ID,
      scope: 'openid profile email',
      sub: tokenData.user.sub,
      exp: Math.floor(tokenData.expires_at / 1000),
      iat: Math.floor(Date.now() / 1000),
      token_type: 'Bearer'
    });
  };

  // Test dashboard for comprehensive OIDC validation testing
  public testDashboard = (req: Request, res: Response): void => {
    const protocol = req.headers['x-forwarded-proto'] || req.protocol || 'http';
    const host = req.headers['x-forwarded-host'] || req.get('host') || 'localhost:5000';
    const testRunner = new OidcTestRunner(`${protocol}://${host}`);
    const groupedTests = testRunner.generateAllTestUrls();
    const tokenCommands = testRunner.generateTokenTestCommands();

    const dashboard = `
      <!DOCTYPE html>
      <html>
      <head>
          <title>🧪 OIDC Test Dashboard - Comprehensive Validation Suite</title>
          <style>
              body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; background: #f8f9fa; }
              .header { text-align: center; margin-bottom: 40px; }
              .test-category { background: white; margin: 20px 0; padding: 25px; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
              .test-category h3 { margin: 0 0 20px 0; padding: 15px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border-radius: 8px; }
              .test-item { margin: 15px 0; padding: 15px; border: 1px solid #e9ecef; border-radius: 8px; background: #f8f9fa; }
              .test-item h4 { margin: 0 0 8px 0; color: #495057; }
              .test-item p { margin: 5px 0; color: #6c757d; font-size: 14px; }
              .test-url { background: #e9ecef; padding: 10px; border-radius: 5px; font-family: monospace; font-size: 12px; word-break: break-all; margin: 10px 0; }
              .expected { color: #28a745; font-weight: 500; }
              .error { color: #dc3545; font-weight: 500; }
              .warning { color: #ffc107; font-weight: 500; }
              .token-tests { background: white; margin: 20px 0; padding: 25px; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
              .curl-command { background: #2d3748; color: #e2e8f0; padding: 15px; border-radius: 8px; font-family: monospace; font-size: 12px; white-space: pre-wrap; margin: 10px 0; overflow-x: auto; }
              .badge { display: inline-block; padding: 3px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; text-transform: uppercase; }
              .badge-basic { background: #007bff; color: white; }
              .badge-security { background: #dc3545; color: white; }
              .badge-pkce { background: #28a745; color: white; }
              .badge-edge { background: #ffc107; color: black; }
              .badge-malicious { background: #6f42c1; color: white; }
              .test-button { display: inline-block; padding: 8px 16px; background: #007bff; color: white; text-decoration: none; border-radius: 5px; font-size: 12px; margin: 5px 5px 0 0; }
              .test-button:hover { background: #0056b3; }
              .stats { display: flex; gap: 20px; margin: 20px 0; }
              .stat-box { flex: 1; background: white; padding: 20px; border-radius: 8px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
              .stat-number { font-size: 24px; font-weight: bold; color: #495057; }
              .stat-label { color: #6c757d; font-size: 14px; margin-top: 5px; }
          </style>
      </head>
      <body>
          <div class="header">
              <h1>🧪 OIDC Test Dashboard</h1>
              <p>Comprehensive validation suite for production-grade OIDC implementation</p>
          </div>

          <div class="stats">
              <div class="stat-box">
                  <div class="stat-number">${OIDC_TEST_SCENARIOS.length}</div>
                  <div class="stat-label">Total Test Scenarios</div>
              </div>
              <div class="stat-box">
                  <div class="stat-number">${Object.keys(groupedTests).length}</div>
                  <div class="stat-label">Test Categories</div>
              </div>
              <div class="stat-box">
                  <div class="stat-number">${tokenCommands.length}</div>
                  <div class="stat-label">Token Endpoint Tests</div>
              </div>
          </div>

          ${Object.entries(groupedTests).map(([category, tests]) => `
              <div class="test-category">
                  <h3>
                      <span class="badge badge-${category}">${category}</span>
                      ${category.replace('_', ' ').toUpperCase()} Tests (${tests.length})
                  </h3>
                  ${tests.map(({ scenario, url }) => `
                      <div class="test-item">
                          <h4>${scenario.name.replace(/_/g, ' ')}</h4>
                          <p>${scenario.description}</p>
                          <div class="test-url">${url}</div>
                          <div>
                              <span class="expected">Expected: ${scenario.expectedResult}</span>
                              ${scenario.expectedError ? `<span class="error"> | Error: ${scenario.expectedError}</span>` : ''}
                          </div>
                          <a href="${url}" class="test-button" target="_blank">🧪 Test This Scenario</a>
                          <button onclick="navigator.clipboard.writeText('${url}')" class="test-button">📋 Copy URL</button>
                      </div>
                  `).join('')}
              </div>
          `).join('')}

          <div class="token-tests">
              <h3>🔐 Token Endpoint Security Tests</h3>
              <p>Test the token endpoint with various authentication scenarios:</p>
              ${tokenCommands.map((command, index) => `
                  <div class="test-item">
                      <h4>Token Test ${index + 1}</h4>
                      <div class="curl-command">${command}</div>
                      <button onclick="navigator.clipboard.writeText(\`${command.replace(/`/g, '\\`')}\`)" class="test-button">📋 Copy Command</button>
                  </div>
              `).join('')}
          </div>

          <div class="test-category">
              <h3>📚 Testing Instructions</h3>
              <div class="test-item">
                  <h4>How to Use This Dashboard</h4>
                  <p><strong>1. Authorization Tests:</strong> Click the test buttons above to run each OIDC scenario. Check browser developer tools for detailed logs.</p>
                  <p><strong>2. Token Endpoint Tests:</strong> Copy and run the curl commands in your terminal to test token exchange security.</p>
                  <p><strong>3. Passport Integration:</strong> After testing individual scenarios, try the full flow through your application.</p>
                  <p><strong>4. Expected Behaviors:</strong></p>
                  <ul>
                      <li><span class="expected">Success scenarios</span> should complete the login flow</li>
                      <li><span class="error">Error scenarios</span> should be rejected with proper error messages</li>
                      <li><span class="warning">Security scenarios</span> should log warnings but may still proceed</li>
                  </ul>
              </div>
          </div>

          <script>
              console.log('🧪 OIDC Test Dashboard loaded - Check network tab for detailed request/response logs');

              // Add click tracking for better debugging
              document.querySelectorAll('.test-button').forEach(button => {
                  button.addEventListener('click', (e) => {
                      if (e.target.href) {
                          console.log('🔍 Testing scenario:', e.target.href);
                      }
                  });
              });
          </script>
      </body>
      </html>
    `;

    res.send(dashboard);
  };

  constructor() {
    // Set the public key in environment for JWT validation fallback
    process.env.MOCK_OIDC_PUBLIC_KEY = this.keyPair.publicKey;
    console.log('🎭 Mock OIDC public key set in environment for JWT validation');
  }

  // Get public key (for debugging/testing)
  public getPublicKey(): string {
    return this.keyPair.publicKey;
  }
}
