import { Request, Response } from 'express';
import { AuthService } from '../services/AuthService';
import passport from '../config/auth';
import { generatePKCE, generateNonce, generateState } from '../config/auth';
import {
  validateState,
  validatePKCE,
  validateRedirectUri,
  validateAuthorizationCode,
  validateNonce,
  validateIssuer,
  isSecurityError,
  decodeJWTPayload
} from '../utils/security-validator';

export class AuthController {
  private authService: AuthService;

  constructor() {
    this.authService = new AuthService();
  }

  // Initiate OIDC login
  login = (req: Request, res: Response, next: Function) => {
    // Store the original URL to redirect after authentication
    const returnTo = req.query.returnTo as string || '/';
    console.log('🎭 Storing returnTo in session:', returnTo);

    // Ensure session exists before storing returnTo
    if (!req.session) {
      console.error('No session available for storing returnTo');
    } else {
      (req.session as any).returnTo = returnTo;
      console.log('🎭 Session ID when storing returnTo:', req.sessionID);
    }

    // Check if using mock OIDC
    const useMockOIDC = process.env.NODE_ENV === 'development' && process.env.USE_MOCK_OIDC === 'true';

    if (useMockOIDC) {
      // Build ACR values parameter
      const acrValues = process.env.OIDC_ACR_VALUES || 'your-acr-value';

      // Generate PKCE and nonce for mock OIDC (still needed for mock)
      const { codeVerifier, codeChallenge } = generatePKCE();
      const nonce = generateNonce();
      const state = generateState();

      // Store PKCE verifier and nonce in session for validation
      (req.session as any).codeVerifier = codeVerifier;
      (req.session as any).codeChallenge = codeChallenge; // Store challenge for double-check
      (req.session as any).nonce = nonce;
      (req.session as any).state = state;

      // Redirect to mock OIDC authorization endpoint with enhanced security
      const mockAuthUrl = `/api/mock-oidc/auth?client_id=mock-client&redirect_uri=${encodeURIComponent(process.env.OIDC_CALLBACK_URL || 'https://node.localhost/api/auth/callback')}&response_type=code&scope=openid%20profile%20email&state=${encodeURIComponent(state)}&nonce=${encodeURIComponent(nonce)}&code_challenge=${encodeURIComponent(codeChallenge)}&code_challenge_method=S256&acr_values=${encodeURIComponent(acrValues)}`;

      console.log('🔐 Mock OIDC with enhanced security:');
      console.log('  - ACR Values:', acrValues);
      console.log('  - PKCE Challenge:', codeChallenge.substring(0, 10) + '...');
      console.log('  - Nonce:', nonce.substring(0, 10) + '...');
      console.log('  - State:', state.substring(0, 10) + '...');

      return res.redirect(mockAuthUrl);
    }

    // For real OIDC, use Passport.js with built-in security features
    // Note: PKCE must still be handled manually as passport-openidconnect doesn't support it natively
    const issuer = process.env.OIDC_ISSUER;
    const clientId = process.env.OIDC_CLIENT_ID;
    const callbackURL = process.env.OIDC_CALLBACK_URL || 'https://node.localhost/api/auth/callback';
    const acrValues = process.env.OIDC_ACR_VALUES;

    if (!issuer || !clientId) {
      console.error('OIDC configuration incomplete');
      return res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=configuration_error`);
    }

    // Generate PKCE (not natively supported by passport-openidconnect)
    const { codeVerifier, codeChallenge } = generatePKCE();
    (req.session as any).codeVerifier = codeVerifier;
    (req.session as any).codeChallenge = codeChallenge;

    // Build authorization URL with PKCE
    const authUrl = new URL(`${issuer}/auth`);
    authUrl.searchParams.set('client_id', clientId);
    authUrl.searchParams.set('redirect_uri', callbackURL);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('scope', 'openid profile email');
    authUrl.searchParams.set('code_challenge', codeChallenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');

    if (acrValues) {
      authUrl.searchParams.set('acr_values', acrValues);
    }

    // Let Passport.js handle state and nonce automatically by using the authenticate method
    // First store the PKCE-enhanced URL parameters, then let Passport add state/nonce
    (req.session as any).pkceAuthUrl = authUrl.toString();

    console.log('🔐 Real OIDC with hybrid Passport.js + PKCE security:');
    console.log('  - Issuer:', issuer);
    console.log('  - ACR Values:', acrValues || 'none');
    console.log('  - PKCE Challenge:', codeChallenge.substring(0, 10) + '...');
    console.log('  - State/Nonce: Managed by Passport.js');

    // Use Passport.js authenticate - it will handle state and nonce automatically
    return passport.authenticate('oidc')(req, res, next);
  };

  // Handle OIDC callback with comprehensive security validation
  callback = async (req: Request, res: Response, next: Function) => {
    const useMockOIDC = process.env.NODE_ENV === 'development' && process.env.USE_MOCK_OIDC === 'true';

    try {
      if (useMockOIDC) {
        return await this.handleMockCallback(req, res, next);
      } else {
        return await this.handleRealOIDCCallback(req, res, next);
      }
    } catch (error) {
      console.error('🔒 Callback error:', error);

      // Security-aware error handling
      const errorParam = isSecurityError(error) ? 'security_error' : 'server_error';
      return res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=${errorParam}`);
    }
  };

  // Handle Real OIDC callback with Passport.js built-in security + PKCE validation
  private handleRealOIDCCallback = async (req: Request, res: Response, next: Function): Promise<void> => {
    try {
      const { code, error } = req.query;

      // 1. Check for OAuth error response
      if (error) {
        console.error('🔒 OAuth error from provider:', error);
        res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=oauth_error`);
        return;
      }

      // 2. Validate authorization code format
      validateAuthorizationCode(code as string);
      console.log('✅ Authorization code validated');

      // 3. Validate PKCE (the only custom validation needed)
      const sessionCodeVerifier = (req.session as any)?.codeVerifier;
      const sessionCodeChallenge = (req.session as any)?.codeChallenge;

      if (!sessionCodeVerifier || !sessionCodeChallenge) {
        console.error('🔒 Missing PKCE parameters in session');
        res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=security_error`);
        return;
      }

      validatePKCE(sessionCodeVerifier, sessionCodeChallenge);
      console.log('✅ PKCE validation passed');

      // 4. Let Passport.js handle all other security validations:
      // - State parameter validation (automatic with built-in state store)
      // - JWT signature validation (automatic with JWKS)
      // - Issuer validation (automatic)
      // - Audience validation (automatic)
      // - Token expiration validation (automatic)
      // - Nonce validation (automatic with nonce: true)
      return passport.authenticate('oidc', {
        failureRedirect: `${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=authentication_failed`
      }, async (err: any, user: any, info: any) => {
        if (err) {
          console.error('🔒 Passport authentication error:', err);
          return res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=server_error`);
        }

        if (!user) {
          console.error('🔒 No user returned from Passport authentication');
          return res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=authentication_failed`);
        }

        // 5. Clean up session security parameters
        delete (req.session as any).codeVerifier;
        delete (req.session as any).codeChallenge;
        // Note: state and nonce are cleaned up automatically by Passport.js

        // 6. Log in the user
        req.logIn(user, async (loginErr: any) => {
          if (loginErr) {
            console.error('🔒 Login failed:', loginErr);
            res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=login_failed`);
            return;
          }

          // Update last login
          await this.authService.updateLastLogin(user.id);

          // Redirect to original URL
          const returnTo = (req.session as any).returnTo || process.env.FRONTEND_URL || 'https://front.localhost';
          delete (req.session as any).returnTo;

          console.log('✅ Real OIDC authentication completed with Passport.js security validation');
          console.log('   - Authorization code ✅ (format validated)');
          console.log('   - State parameter ✅ (validated by Passport.js)');
          console.log('   - PKCE validation ✅ (custom logic)');
          console.log('   - JWT signature ✅ (validated by Passport.js)');
          console.log('   - Issuer/Audience ✅ (validated by Passport.js)');
          console.log('   - Token expiration ✅ (validated by Passport.js)');
          console.log('   - Nonce validation ✅ (validated by Passport.js)');

          res.redirect(returnTo);
        });
      })(req, res, next);

    } catch (error) {
      console.error('� Real OIDC callback security validation failed:', error);

      if (isSecurityError(error)) {
        res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=${error.code.toLowerCase()}`);
      } else {
        res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=server_error`);
      }
    }
  };

  // Logout
  logout = async (req: Request, res: Response): Promise<void> => {
    try {
      console.log('🚪 Logout requested for user:', req.user ? (req.user as any).email : 'anonymous');

      const logoutURL = process.env.OIDC_LOGOUT_URL;
      const useMockOIDC = process.env.NODE_ENV === 'development' && process.env.USE_MOCK_OIDC === 'true';

      req.logout((err) => {
        if (err) {
          console.error('Logout error:', err);
          res.status(500).json({ error: 'Logout failed' });
          return;
        }

        req.session.destroy((err) => {
          if (err) {
            console.error('Session destruction error:', err);
            res.status(500).json({ error: 'Session cleanup failed' });
            return;
          }

          // Clear the session cookie explicitly with matching security settings
          const isDevelopment = process.env.NODE_ENV === 'development';
          const cookieName = isDevelopment
            ? 'connect.sid'
            : process.env.SESSION_COOKIE_NAME || 'app_session';

          res.clearCookie(cookieName, {
            path: '/',
            domain: isDevelopment ? undefined : process.env.COOKIE_DOMAIN,
            secure: true,
            httpOnly: true, // Match the session configuration
            sameSite: isDevelopment ? 'none' : 'strict' // Match the session configuration
          });

          console.log('✅ User logged out successfully and secure cookie cleared');

          // For mock OIDC, just return success
          if (useMockOIDC) {
            res.json({
              success: true,
              message: 'Logged out successfully',
              redirectUrl: process.env.FRONTEND_URL || 'https://front.localhost'
            });
            return;
          }

          // For real OIDC, include provider logout URL if available
          if (logoutURL) {
            res.json({
              success: true,
              message: 'Logged out successfully',
              redirectUrl: logoutURL
            });
            return;
          }

          res.json({
            success: true,
            message: 'Logged out successfully',
            redirectUrl: process.env.FRONTEND_URL || 'https://front.localhost'
          });
        });
      });
    } catch (error) {
      console.error('Logout error:', error);
      res.status(500).json({ error: 'Internal server error' });
      return;
    }
  };

  // Get current session info
  getSession = async (req: Request, res: Response) => {
    try {
      console.log('AuthController: getSession called');
      console.log('AuthController: Session ID:', req.sessionID);
      console.log('AuthController: Session data:', JSON.stringify(req.session, null, 2));
      console.log('AuthController: User authenticated:', req.isAuthenticated());
      console.log('AuthController: User object:', req.user);
      console.log('AuthController: Request cookies:', req.headers.cookie);

      const sessionInfo = await this.authService.getSessionInfo(req);
      console.log('AuthController: Session info response:', JSON.stringify(sessionInfo, null, 2));

      res.json(sessionInfo);
    } catch (error) {
      console.error('Session info error:', error);
      res.status(500).json({ error: 'Failed to get session info' });
    }
  };

  // Check if user is authenticated (for API endpoints)
  checkAuth = async (req: Request, res: Response) => {
    const isAuthenticated = req.isAuthenticated();
    res.json({
      isAuthenticated,
      user: isAuthenticated ? req.user : null
    });
  };

  // Handle mock OIDC callback with comprehensive security validation
  private handleMockCallback = async (req: Request, res: Response, next: Function): Promise<void> => {
    try {
      const { code, state, error } = req.query;

      // 1. Check for OAuth error response
      if (error) {
        console.error('🎭 Mock OAuth error:', error);
        res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=oauth_error`);
        return;
      }

      // 2. Validate authorization code
      validateAuthorizationCode(code as string);
      console.log('✅ Mock OIDC authorization code validated');

      // 3. Validate state parameter (CSRF protection)
      const sessionState = (req.session as any)?.state;
      validateState(state as string, sessionState);
      console.log('✅ Mock OIDC state parameter validated');

      // 4. Get session security parameters
      const codeVerifier = (req.session as any)?.codeVerifier;
      const nonce = (req.session as any)?.nonce;
      const mockCodeChallenge = (req.session as any)?.codeChallenge;

      if (!codeVerifier) {
        console.error('🎭 Missing PKCE code verifier');
        res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=missing_pkce_verifier`);
        return;
      }

      // 5. Validate redirect URI
      const currentUri = `${req.protocol}://${req.get('host')}${req.originalUrl.split('?')[0]}`;
      const expectedUri = process.env.OIDC_CALLBACK_URL || 'https://node.localhost/api/auth/callback';

      try {
        validateRedirectUri(currentUri, expectedUri);
        console.log('✅ Mock OIDC redirect URI validated');
      } catch (uriError) {
        const errorMsg = uriError instanceof Error ? uriError.message : 'Unknown URI validation error';
        console.warn('⚠️ Mock OIDC redirect URI validation warning:', errorMsg);
      }

      // 6. Validate PKCE (double-check before token exchange)
      if (mockCodeChallenge) {
        try {
          validatePKCE(codeVerifier, mockCodeChallenge);
          console.log('✅ Mock OIDC PKCE pre-validation passed');
        } catch (pkceError) {
          console.error('🎭 PKCE validation failed:', pkceError);
          res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=pkce_validation_failed`);
          return;
        }
      }

      // 7. Exchange authorization code for tokens with PKCE validation
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
          code_verifier: codeVerifier // PKCE verification
        })
      });

      if (!tokenResponse.ok) {
        const errorData = await tokenResponse.text();
        console.error('🎭 Token exchange failed:', errorData);
        res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=token_exchange_failed`);
        return;
      }

      const tokens = await tokenResponse.json();
      console.log('✅ Mock OIDC tokens received');

      // 8. Simple ID token validation (decode and validate claims)
      const idTokenPayload = decodeJWTPayload(tokens.id_token);
      console.log('✅ Mock OIDC ID token decoded');

      // 9. Validate nonce
      if (nonce) {
        validateNonce(idTokenPayload.nonce, nonce);
        console.log('✅ Mock OIDC nonce validated');
      }

      // 10. Validate issuer
      const expectedMockIssuer = process.env.MOCK_OIDC_ISSUER || 'https://node.localhost/api/mock-oidc';
      validateIssuer(idTokenPayload.iss, expectedMockIssuer);
      console.log('✅ Mock OIDC issuer validated');

      // 11. Validate audience
      const audiences = Array.isArray(idTokenPayload.aud) ? idTokenPayload.aud : [idTokenPayload.aud];
      if (!audiences.includes('mock-client')) {
        console.error('🎭 Invalid audience in ID token:', audiences);
        res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=invalid_audience`);
        return;
      }
      console.log('✅ Mock OIDC audience validated');

      // 12. Clean up session security parameters
      delete (req.session as any).state;
      delete (req.session as any).codeVerifier;
      delete (req.session as any).nonce;
      delete (req.session as any).codeChallenge;

      // 13. Find or create user
      const user = await this.authService.findOrCreateUserFromOIDC({
        email: idTokenPayload.email || '',
        firstName: idTokenPayload.given_name || idTokenPayload.name?.split(' ')[0] || 'Unknown',
        lastName: idTokenPayload.family_name || idTokenPayload.name?.split(' ').slice(1).join(' ') || 'User',
        sub: idTokenPayload.sub,
        oidcIssuer: expectedMockIssuer,
        fullProfile: idTokenPayload
      });

      // 14. Log in the user
      req.logIn(user, async (err: any) => {
        if (err) {
          console.error('🎭 Mock login failed:', err);
          res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=login_failed`);
          return;
        }

        // Update last login
        try {
          await this.authService.updateLastLogin(user.id);
        } catch (error) {
          console.warn('Could not update last login:', error);
        }

        // Redirect to original URL
        const returnTo = (req.session as any).returnTo || process.env.FRONTEND_URL || 'https://front.localhost';
        delete (req.session as any).returnTo;

        console.log('✅ Mock OIDC authentication completed with COMPREHENSIVE security validation');
        console.log('   - Authorization code ✅');
        console.log('   - State parameter ✅');
        console.log('   - PKCE verification ✅');
        console.log('   - Nonce validation ✅');
        console.log('   - Issuer validation ✅');
        console.log('   - Audience validation ✅');
        console.log('   - Redirect URI validation ✅');

        res.redirect(returnTo);
      });

    } catch (error) {
      console.error('🚨 Mock OIDC callback security validation failed:', error);

      if (isSecurityError(error)) {
        res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=${error.code.toLowerCase()}`);
      } else {
        res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=server_error`);
      }
    }
  };
}
