import { Request, Response } from 'express';
import crypto from 'crypto';
import { BaseAuthStrategy, AuthParams } from './BaseAuthStrategy';
import { generatePKCE } from '../../config/auth';
import { TokenInfo } from '../../middleware/security';

export class MockOIDCStrategy extends BaseAuthStrategy {
  generateAuthParams(): AuthParams {
    const { codeVerifier, codeChallenge } = generatePKCE();
    const nonce = crypto.randomBytes(16).toString('base64url');
    const state = crypto.randomBytes(16).toString('base64url');
    const acrValues = process.env.OIDC_ACR_VALUES || 'your-acr-value';

    return { codeVerifier, codeChallenge, nonce, state, acrValues };
  }

  initiateLogin(req: Request, res: Response, next: Function): void {
    const params = this.generateAuthParams();
    this.storeInSession(req, params);

    const callbackURL = process.env.OIDC_CALLBACK_URL || 'https://node.localhost/api/auth/callback';
    const mockAuthUrl = `/api/mock-oidc/auth?client_id=mock-client&redirect_uri=${encodeURIComponent(callbackURL)}&response_type=code&scope=openid%20profile%20email&state=${encodeURIComponent(params.state!)}&nonce=${encodeURIComponent(params.nonce!)}&code_challenge=${encodeURIComponent(params.codeChallenge!)}&code_challenge_method=S256&acr_values=${encodeURIComponent(params.acrValues!)}`;

    console.log('🎭 Mock OIDC with enhanced security:');
    console.log('  - ACR Values:', params.acrValues);
    console.log('  - PKCE Challenge:', params.codeChallenge!.substring(0, 10) + '...');
    console.log('  - Nonce:', params.nonce!.substring(0, 10) + '...');
    console.log('  - State:', params.state!.substring(0, 10) + '...');

    res.redirect(mockAuthUrl);
  }

  async handleCallback(req: Request, res: Response, next: Function): Promise<void> {
    const { code, state, error } = req.query;

    // 1. Check for OAuth error response
    if (error) {
      console.error('🎭 Mock OAuth error:', error);
      res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=oauth_error`);
      return;
    }

    // 2. Validate authorization code
    this.validateAuthorizationCode(code as string);
    console.log('✅ Mock OIDC authorization code validated');

    // 3. Validate state parameter (CSRF protection)
    const sessionState = this.getFromSession(req, 'state');
    this.validateState(state as string, sessionState);
    console.log('✅ Mock OIDC state parameter validated');

    // 4. Get session security parameters
    const codeVerifier = this.getFromSession(req, 'codeVerifier');
    const nonce = this.getFromSession(req, 'nonce');
    const mockCodeChallenge = this.getFromSession(req, 'codeChallenge');

    if (!codeVerifier) {
      console.error('🎭 Missing PKCE code verifier');
      res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=missing_pkce_verifier`);
      return;
    }

    // 5. Validate redirect URI
    const currentUri = `${req.protocol}://${req.get('host')}${req.originalUrl.split('?')[0]}`;
    const expectedUri = process.env.OIDC_CALLBACK_URL || 'https://node.localhost/api/auth/callback';

    try {
      this.validateRedirectUri(currentUri, expectedUri);
      console.log('✅ Mock OIDC redirect URI validated');
    } catch (uriError) {
      const errorMsg = uriError instanceof Error ? uriError.message : 'Unknown URI validation error';
      console.warn('⚠️ Mock OIDC redirect URI validation warning:', errorMsg);
    }

    // 6. Validate PKCE
    if (mockCodeChallenge) {
      try {
        this.validatePKCE(codeVerifier, mockCodeChallenge);
        console.log('✅ Mock OIDC PKCE pre-validation passed');
      } catch (pkceError) {
        console.error('🎭 PKCE validation failed:', pkceError);
        res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=pkce_validation_failed`);
        return;
      }
    }

    // 7. Exchange authorization code for tokens
    const tokenResponse = await fetch('http://localhost:5000/api/mock-oidc/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        code: (code as string),
        client_id: 'mock-client',
        redirect_uri: process.env.OIDC_CALLBACK_URL || 'https://node.localhost/api/auth/callback',
        code_verifier: codeVerifier
      })
    });

    if (!tokenResponse.ok) {
      const errorData = await tokenResponse.text();
      console.error('🎭 Token exchange failed:', errorData);
      res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=token_exchange_failed`);
      return;
    }

    const tokens = await tokenResponse.json();
    const { id_token, access_token, refresh_token } = tokens;

    if (!id_token || !access_token) {
      console.error('🎭 Missing tokens in response');
      res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=missing_tokens`);
      return;
    }

    // Store token information in session for token-aware session management
    const tokenInfo: TokenInfo = {
      accessToken: access_token,
      idToken: id_token,
      refreshToken: refresh_token,
      expiresAt: Date.now() + ((tokens.expires_in || 3600) * 1000),
      lastRefresh: Date.now()
    };

    // Decode ID token to get expiration
    const idTokenPayload = this.decodeJWTPayload(id_token);
    tokenInfo.tokenExpiry = idTokenPayload.exp * 1000; // Convert to milliseconds

    // Set refresh token expiration (mock tokens typically have longer refresh expiry)
    if (refresh_token) {
      tokenInfo.refreshExpiry = Date.now() + (7 * 24 * 60 * 60 * 1000); // 7 days
    }

    // Store token info in session
    (req.session as any).tokenInfo = tokenInfo;

    console.log('🎭 Mock token info stored:', {
      hasAccessToken: !!access_token,
      hasIdToken: !!id_token,
      hasRefreshToken: !!refresh_token,
      tokenExpiresAt: new Date(tokenInfo.tokenExpiry!).toISOString(),
      refreshExpiresAt: tokenInfo.refreshExpiry ? new Date(tokenInfo.refreshExpiry).toISOString() : 'not set'
    });

    // 8. Validate nonce in ID token
    this.validateNonce(idTokenPayload.nonce, nonce);
    console.log('✅ Mock OIDC nonce validated');

    // 9. Validate issuer
    this.validateIssuer(idTokenPayload.iss, process.env.MOCK_OIDC_ISSUER || 'https://node.localhost/api/mock-oidc');
    console.log('✅ Mock OIDC issuer validated');

    // 10. Create or update user
    const user = await this.findOrCreateUser({
      sub: idTokenPayload.sub,
      issuer: idTokenPayload.iss,
      email: idTokenPayload.email,
      given_name: idTokenPayload.given_name,
      family_name: idTokenPayload.family_name,
      profile: idTokenPayload
    });

    // 11. Clean up session security parameters
    this.clearSessionParams(req, ['codeVerifier', 'codeChallenge', 'nonce', 'state']);

    // 12. Log in the user
    req.logIn(user, async (loginErr: any) => {
      if (loginErr) {
        console.error('🔒 Login failed:', loginErr);
        res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=login_failed`);
        return;
      }

      // Update last login
      await this.updateLastLogin(user.id);

      // Redirect to original URL
      const returnTo = this.getFromSession(req, 'returnTo') || process.env.FRONTEND_URL || 'https://front.localhost';
      this.clearSessionParams(req, ['returnTo']);

      console.log(`✅ Mock OIDC authentication successful for user: ${user.email}`);
      res.redirect(returnTo);
    });
  }

  async validateCallback(req: Request): Promise<boolean> {
    // Mock validation logic
    return true;
  }
}
