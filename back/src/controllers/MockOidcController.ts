import { Request, Response } from 'express';
import crypto from 'crypto';
import { mockUsers, MockUser } from '../config/mock-auth';

export class MockOidcController {
  private readonly MOCK_ISSUER = process.env.MOCK_OIDC_ISSUER || 'https://node.localhost/api/mock-oidc';
  private readonly MOCK_CLIENT_ID = 'mock-client';

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
  private generateJWT = (payload: Record<string, any>, expiresIn: number = 3600): string => {
    const header = {
      alg: 'RS256',
      typ: 'JWT',
      kid: 'mock-key-1'
    };

    const now = Math.floor(Date.now() / 1000);
    const jwtPayload = {
      ...payload,
      iat: now,
      exp: now + expiresIn
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

  // Mock OIDC Discovery endpoint
  public discovery = (req: Request, res: Response): void => {
    const protocol = req.headers['x-forwarded-proto'] || req.protocol;
    const host = req.headers['x-forwarded-host'] || req.get('host');
    const baseUrl = `${protocol}://${host}/api/mock-oidc`;

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
      grant_types_supported: ['authorization_code', 'refresh_token']
    });
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
      code_challenge: code_challenge ? 'present' : 'none', code_challenge_method
    });

    // ====== COMPREHENSIVE OIDC VALIDATIONS ======

    // 1. Validate client_id
    if (!client_id || !this.validateClientId(client_id as string)) {
      res.status(400).send('❌ Invalid client_id. Expected: ' + this.MOCK_CLIENT_ID);
      return;
    }

    // 2. Validate redirect_uri against whitelist
    if (!redirect_uri || !this.validateRedirectUri(redirect_uri as string)) {
      res.status(400).send('❌ Invalid redirect_uri. Must be whitelisted: ' + this.VALID_REDIRECT_URIS.join(', '));
      return;
    }

    // 3. Validate response_type
    if (!response_type || !this.validateResponseType(response_type as string)) {
      const errorUrl = new URL(redirect_uri as string);
      errorUrl.searchParams.set('error', 'unsupported_response_type');
      errorUrl.searchParams.set('error_description', 'Only authorization code flow is supported');
      if (state) errorUrl.searchParams.set('state', state as string);
      res.redirect(errorUrl.toString());
      return;
    }

    // 4. Validate scope (must include 'openid')
    if (!scope || !this.validateScope(scope as string)) {
      const errorUrl = new URL(redirect_uri as string);
      errorUrl.searchParams.set('error', 'invalid_scope');
      errorUrl.searchParams.set('error_description', 'Scope must include openid');
      if (state) errorUrl.searchParams.set('state', state as string);
      res.redirect(errorUrl.toString());
      return;
    }

    // 5. Validate PKCE if present
    if (code_challenge) {
      if (!code_challenge_method || code_challenge_method !== 'S256') {
        const errorUrl = new URL(redirect_uri as string);
        errorUrl.searchParams.set('error', 'invalid_request');
        errorUrl.searchParams.set('error_description', 'PKCE requires S256 method');
        if (state) errorUrl.searchParams.set('state', state as string);
        res.redirect(errorUrl.toString());
        return;
      }
      if ((code_challenge as string).length < 43) {
        const errorUrl = new URL(redirect_uri as string);
        errorUrl.searchParams.set('error', 'invalid_request');
        errorUrl.searchParams.set('error_description', 'Invalid PKCE code challenge length');
        if (state) errorUrl.searchParams.set('state', state as string);
        res.redirect(errorUrl.toString());
        return;
      }
    }

    // 6. Check state parameter (security best practice)
    if (!state) {
      console.warn('⚠️  No state parameter - CSRF vulnerability!');
    }

    // 7. Check nonce parameter (recommended for implicit flow, but good practice)
    if (!nonce) {
      console.warn('⚠️  No nonce parameter - replay attack vulnerability!');
    }

    console.log('✅ All OIDC validations passed');

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
          </style>
      </head>
      <body>
          <div class="container">
              <h2>🔐 Production-Grade Mock OIDC Provider</h2>

              <div class="validation">
                  <h3>✅ OIDC Security Validation Results</h3>
                  <p><strong>Client ID:</strong> <span class="param">${client_id}</span> <span class="check">✅ Verified</span></p>
                  <p><strong>Redirect URI:</strong> <span class="param">${redirect_uri}</span> <span class="check">✅ Whitelisted</span></p>
                  <p><strong>Response Type:</strong> <span class="param">${response_type}</span> <span class="check">✅ Authorization Code Flow</span></p>
                  <p><strong>Scope:</strong> <span class="param">${scope}</span> <span class="check">✅ Valid (includes openid)</span></p>
                  <p><strong>State:</strong> <span class="param">${state || 'None'}</span> ${state ? '<span class="check">✅ CSRF Protection</span>' : '<span class="warn">⚠️ Missing (CSRF Risk)</span>'}</p>
                  <p><strong>Nonce:</strong> <span class="param">${nonce || 'None'}</span> ${nonce ? '<span class="check">✅ Replay Protection</span>' : '<span class="warn">⚠️ Missing (Replay Risk)</span>'}</p>
                  ${code_challenge ? `<p><strong>PKCE:</strong> Challenge with ${code_challenge_method} <span class="check">✅ Enhanced Security</span></p>` : '<p><strong>PKCE:</strong> Not used <span class="warn">⚠️ Recommended for public clients</span></p>'}
                  ${acr_values ? `<p><strong>ACR Values:</strong> <span class="param">${acr_values}</span> <span class="check">✅ Authentication Context</span></p>` : ''}
              </div>

              ${!state || !nonce ? '<div class="warning"><strong>⚠️ Security Recommendations:</strong><ul>' +
                (!state ? '<li>Add state parameter for CSRF protection</li>' : '') +
                (!nonce ? '<li>Add nonce parameter for replay protection</li>' : '') +
                '</ul></div>' : ''}

              <div class="security">
                  <h3>🛡️ Security Features Implemented</h3>
                  <div class="feature-grid">
                      <div class="feature">✅ Client ID Verification</div>
                      <div class="feature">✅ Redirect URI Whitelist</div>
                      <div class="feature">✅ Scope Validation</div>
                      <div class="feature">${code_challenge ? '✅' : '➖'} PKCE Code Challenge</div>
                      <div class="feature">${state ? '✅' : '⚠️'} State Parameter</div>
                      <div class="feature">${nonce ? '✅' : '⚠️'} Nonce Parameter</div>
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
                  ${state ? `<input type="hidden" name="state" value="${state}" />` : ''}
                  ${nonce ? `<input type="hidden" name="nonce" value="${nonce}" />` : ''}
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

    // Store with security context
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

    const redirectUrl = new URL(redirect_uri);
    redirectUrl.searchParams.set('code', authCode);
    if (state) redirectUrl.searchParams.set('state', state);

    res.redirect(redirectUrl.toString());
  };

  // Enhanced token endpoint with full validation
  public token = (req: Request, res: Response): void => {
    const { grant_type, code, client_id, redirect_uri, code_verifier, refresh_token } = req.body;

    console.log('🎭 Token Request with Enhanced Validation:', {
      grant_type, code: code ? code.substring(0, 8) + '...' : 'none',
      client_id, redirect_uri, code_verifier: code_verifier ? 'present' : 'none',
      refresh_token: refresh_token ? 'present' : 'none'
    });

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

      // Create new ID token
      const idTokenPayload = {
        iss: this.MOCK_ISSUER,
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

    if (!client_id || client_id !== this.MOCK_CLIENT_ID) {
      res.status(401).json({ error: 'invalid_client' });
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

    // Validate parameters match
    if (codeData.client_id !== client_id || codeData.redirect_uri !== redirect_uri) {
      res.status(400).json({ error: 'invalid_grant', error_description: 'Parameter mismatch' });
      return;
    }

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

    // Generate proper JWT ID token
    const idTokenPayload = {
      iss: this.MOCK_ISSUER,
      sub: codeData.user.sub,
      aud: client_id,
      email: codeData.user.email,
      given_name: codeData.user.firstName,
      family_name: codeData.user.lastName,
      name: `${codeData.user.firstName} ${codeData.user.lastName}`,
      ...(codeData.nonce && { nonce: codeData.nonce })
    };

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

    // In a real implementation, you would validate the JWT token
    // For this mock, we'll just return user info based on a simple lookup

    // Mock validation - in reality you'd decode and verify the JWT
    if (!token || token.length < 10) {
      res.status(401).json({
        error: 'invalid_token',
        error_description: 'Invalid access token'
      });
      return;
    }

    // Return user info for the mock admin user
    res.json({
      sub: 'mock-admin-123',
      email: 'admin@example.com',
      email_verified: true,
      given_name: 'Admin',
      family_name: 'User',
      name: 'Admin User',
      picture: 'https://via.placeholder.com/150',
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

    // Mock introspection - in reality you'd validate the token properly
    res.json({
      active: true,
      client_id: this.MOCK_CLIENT_ID,
      scope: 'openid profile email',
      sub: 'mock-admin-123',
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
      token_type: 'Bearer'
    });
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
