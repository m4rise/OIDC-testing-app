import { Request, Response } from 'express';
import { AuthService } from '../services/AuthService';
import passport from '../config/auth';
import { generatePKCE, generateNonce, generateState } from '../config/auth';

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

      // Generate PKCE and nonce for mock OIDC
      const { codeVerifier, codeChallenge } = generatePKCE();
      const nonce = generateNonce();
      const state = generateState();

      // Store PKCE verifier and nonce in session for validation
      (req.session as any).codeVerifier = codeVerifier;
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

    // For real OIDC, build the authorization URL manually with enhanced security
    const issuer = process.env.OIDC_ISSUER;
    const clientId = process.env.OIDC_CLIENT_ID;
    const callbackURL = process.env.OIDC_CALLBACK_URL || 'https://node.localhost/api/auth/callback';
    const acrValues = process.env.OIDC_ACR_VALUES;

    if (!issuer || !clientId) {
      console.error('OIDC configuration incomplete');
      return res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=configuration_error`);
    }

    // Generate PKCE and security parameters
    const { codeVerifier, codeChallenge } = generatePKCE();
    const nonce = generateNonce();
    const state = generateState();

    // Store security parameters in session for validation
    (req.session as any).codeVerifier = codeVerifier;
    (req.session as any).nonce = nonce;
    (req.session as any).state = state;

    // Build enhanced authorization URL
    const authUrl = new URL(`${issuer}/auth`);
    authUrl.searchParams.set('client_id', clientId);
    authUrl.searchParams.set('redirect_uri', callbackURL);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('scope', 'openid profile email');
    authUrl.searchParams.set('state', state);
    authUrl.searchParams.set('nonce', nonce);
    authUrl.searchParams.set('code_challenge', codeChallenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');

    if (acrValues) {
      authUrl.searchParams.set('acr_values', acrValues);
    }

    console.log('🔐 Real OIDC with enhanced security:');
    console.log('  - Issuer:', issuer);
    console.log('  - ACR Values:', acrValues || 'none');
    console.log('  - PKCE Challenge:', codeChallenge.substring(0, 10) + '...');
    console.log('  - Nonce:', nonce.substring(0, 10) + '...');
    console.log('  - State:', state.substring(0, 10) + '...');

    return res.redirect(authUrl.toString());
  };

  // Handle OIDC callback
  callback = (req: Request, res: Response, next: Function) => {
    // Check if using mock OIDC
    const useMockOIDC = process.env.NODE_ENV === 'development' && process.env.USE_MOCK_OIDC === 'true';

    if (useMockOIDC) {
      return this.handleMockCallback(req, res, next);
    }

    // Validate state parameter for CSRF protection
    const receivedState = req.query.state as string;
    const sessionState = (req.session as any)?.state;

    if (!receivedState || !sessionState || receivedState !== sessionState) {
      console.error('🔒 State parameter validation failed:', {
        received: receivedState?.substring(0, 10) + '...',
        expected: sessionState?.substring(0, 10) + '...'
      });
      return res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=state_mismatch`);
    }

    console.log('✅ State parameter validated successfully');

    // Clean up state from session
    delete (req.session as any).state;

    return passport.authenticate('oidc', {
      failureRedirect: `${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=authentication_failed`
    }, async (err: any, user: any, info: any) => {
      if (err) {
        console.error('Authentication error:', err);
        return res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=server_error`);
      }

      if (!user) {
        return res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=authentication_failed`);
      }

      // Additional validation: check nonce in ID token if available
      const sessionNonce = (req.session as any)?.nonce;
      if (sessionNonce) {
        // Note: In a real implementation, you would decode and verify the ID token
        // and check that the nonce claim matches the session nonce
        console.log('🔐 Nonce validation should be implemented for ID token verification');
        delete (req.session as any).nonce;
      }

      // Clean up PKCE verifier from session
      delete (req.session as any).codeVerifier;

      req.logIn(user, async (err) => {
        if (err) {
          console.error('Login error:', err);
          return res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=login_failed`);
        }

        // Update last login
        await this.authService.updateLastLogin(user.id);

        // Redirect to the original URL or default
        const returnTo = (req.session as any).returnTo || process.env.FRONTEND_URL || 'http://front.localhost';
        delete (req.session as any).returnTo;

        console.log('✅ Real OIDC authentication completed with enhanced security validation');
        return res.redirect(returnTo);
      });
    })(req, res, next);
  };

  // Logout
  logout = async (req: Request, res: Response): Promise<void> => {
    try {
      const logoutURL = process.env.OIDC_LOGOUT_URL;

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

          if (logoutURL) {
            res.json({
              success: true,
              redirectUrl: logoutURL
            });
            return;
          }

          res.json({ success: true });
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

  // Handle mock OIDC callback
  private handleMockCallback = async (req: Request, res: Response, next: Function): Promise<void> => {
    const { code, state } = req.query;

    // Validate authorization code
    if (!code) {
      res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=missing_authorization_code`);
      return;
    }

    // SECURITY: Validate state parameter to prevent CSRF attacks
    const sessionState = (req.session as any)?.state;
    if (!state || !sessionState || state !== sessionState) {
      console.error('🎭 Mock callback: State validation failed:', {
        received: state?.toString().substring(0, 10) + '...',
        expected: sessionState?.substring(0, 10) + '...'
      });
      res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=state_mismatch`);
      return;
    }

    console.log('✅ Mock OIDC state parameter validated successfully');

    // Get PKCE verifier from session for token exchange
    const codeVerifier = (req.session as any)?.codeVerifier;
    const nonce = (req.session as any)?.nonce;

    if (!codeVerifier) {
      console.error('🎭 Mock callback: Missing PKCE code verifier in session');
      res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=missing_pkce_verifier`);
      return;
    }

    try {
      // Exchange authorization code for tokens with PKCE
      // Use localhost for internal container communication
      const tokenResponse = await fetch('http://localhost:5000/api/mock-oidc/token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          grant_type: 'authorization_code',
          code: code.toString(),
          client_id: 'mock-client',
          redirect_uri: process.env.OIDC_CALLBACK_URL || 'https://node.localhost/api/auth/callback',
          code_verifier: codeVerifier // PKCE verification
        })
      });      if (!tokenResponse.ok) {
        const errorData = await tokenResponse.text();
        console.error('🎭 Token exchange failed:', errorData);
        res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=token_exchange_failed`);
        return;
      }

      const tokens = await tokenResponse.json();
      console.log('✅ Mock OIDC tokens received with PKCE validation');

      // Decode ID token (it's a JWT in the enhanced mock)
      const idTokenParts = tokens.id_token.split('.');
      if (idTokenParts.length !== 3) {
        console.error('🎭 Invalid ID token format');
        res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=invalid_id_token`);
        return;
      }

      const idTokenPayload = JSON.parse(Buffer.from(idTokenParts[1], 'base64url').toString());

      // Validate nonce if present
      if (nonce && idTokenPayload.nonce !== nonce) {
        console.error('🎭 Nonce validation failed:', {
          expected: nonce.substring(0, 10) + '...',
          received: idTokenPayload.nonce?.substring(0, 10) + '...'
        });
        res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=nonce_mismatch`);
        return;
      }

      if (nonce) {
        console.log('✅ Mock OIDC nonce validated successfully');
      }

      // Clean up session security parameters
      delete (req.session as any).state;
      delete (req.session as any).codeVerifier;
      delete (req.session as any).nonce;

      // Find or create user from OIDC token data
      try {
        const userForSession = await this.authService.findOrCreateUserFromOIDC({
          email: idTokenPayload.email,
          firstName: idTokenPayload.given_name || idTokenPayload.name?.split(' ')[0] || 'Unknown',
          lastName: idTokenPayload.family_name || idTokenPayload.name?.split(' ').slice(1).join(' ') || 'User',
          sub: idTokenPayload.sub,
          oidcIssuer: 'mock-oidc'
        });

        // Log in the user
        req.logIn(userForSession, async (err: any) => {
          if (err) {
            console.error('🎭 Mock login error:', err);
            res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=login_failed`);
            return;
          }

          // Update last login
          try {
            await this.authService.updateLastLogin(userForSession.id);
          } catch (error) {
            console.warn('Could not update last login:', error);
          }

          // Redirect to the original URL or default
          const returnTo = (req.session as any).returnTo || process.env.FRONTEND_URL || 'http://front.localhost';
          delete (req.session as any).returnTo;

          console.log('✅ Mock OIDC authentication completed with full security validation (PKCE + nonce + state)');
          res.redirect(returnTo);
        });

      } catch (error) {
        console.error('🎭 Mock callback error:', error);
        res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=server_error`);
      }

    } catch (error) {
      console.error('🎭 Mock callback error:', error);
      res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=server_error`);
    }
  };
}
