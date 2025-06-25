import { Request, Response } from 'express';
import { AuthService } from '../services/AuthService';
import passport from '../config/auth';

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

      // Redirect to mock OIDC authorization endpoint with acr_values
      const mockAuthUrl = `/api/mock-oidc/auth?client_id=mock-client&redirect_uri=${encodeURIComponent(process.env.OIDC_CALLBACK_URL || 'https://node.localhost/api/auth/callback')}&response_type=code&scope=openid%20profile%20email&state=${req.sessionID}&acr_values=${encodeURIComponent(acrValues)}`;
      console.log('🎭 Redirecting to mock OIDC with acr_values:', acrValues);
      console.log('🎭 Mock auth URL:', mockAuthUrl);
      return res.redirect(mockAuthUrl);
    }

    // For real OIDC, we need to build the authorization URL manually to include acr_values
    const acrValues = process.env.OIDC_ACR_VALUES;

    if (acrValues) {
      // Build custom authorization URL with acr_values
      const issuer = process.env.OIDC_ISSUER;
      const clientId = process.env.OIDC_CLIENT_ID;
      const callbackURL = process.env.OIDC_CALLBACK_URL || 'https://node.localhost/api/auth/callback';
      const state = req.sessionID; // Use session ID as state for CSRF protection

      const authUrl = new URL(`${issuer}/auth`);
      authUrl.searchParams.set('client_id', clientId!);
      authUrl.searchParams.set('redirect_uri', callbackURL);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('scope', 'openid profile email');
      authUrl.searchParams.set('state', state);
      authUrl.searchParams.set('acr_values', acrValues);

      console.log('🔐 Redirecting to OIDC with acr_values:', acrValues);
      return res.redirect(authUrl.toString());
    }

    // Fallback to standard passport authentication without acr_values
    passport.authenticate('oidc', {
      scope: 'openid profile email'
    })(req, res, next);
  };

  // Handle OIDC callback
  callback = (req: Request, res: Response, next: Function) => {
    // Check if using mock OIDC
    const useMockOIDC = process.env.NODE_ENV === 'development' && process.env.USE_MOCK_OIDC === 'true';

    if (useMockOIDC) {
      return this.handleMockCallback(req, res, next);
    }

    return passport.authenticate('oidc', {
      failureRedirect: '/auth/login?error=authentication_failed'
    }, async (err: any, user: any, info: any) => {
      if (err) {
        console.error('Authentication error:', err);
        return res.redirect('/auth/login?error=server_error');
      }

      if (!user) {
        return res.redirect('/auth/login?error=authentication_failed');
      }

      req.logIn(user, async (err) => {
        if (err) {
          console.error('Login error:', err);
          return res.redirect('/auth/login?error=login_failed');
        }

        // Update last login
        await this.authService.updateLastLogin(user.id);

        // Redirect to the original URL or default
        const returnTo = (req.session as any).returnTo || process.env.FRONTEND_URL || 'http://front.localhost';
        delete (req.session as any).returnTo;

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

    if (!code || !code.toString().startsWith('mock_code_')) {
      res.redirect('/auth/login?error=invalid_authorization_code');
      return;
    }

    // SECURITY: Validate state parameter to prevent CSRF attacks
    if (!state || state !== req.sessionID) {
      console.error('🎭 Mock callback: Invalid state parameter. Expected:', req.sessionID, 'Received:', state);
      res.redirect('/auth/login?error=invalid_state');
      return;
    }

    console.log('🎭 Mock callback: State validation successful');

    try {
      // Extract user info from the mock code
      const codeStr = code.toString();
      const [codePrefix, encodedUserInfo] = codeStr.split('.');

      if (!encodedUserInfo) {
        res.redirect('/auth/login?error=invalid_authorization_code');
        return;
      }

      const userInfo = JSON.parse(Buffer.from(encodedUserInfo, 'base64').toString());
      console.log('🎭 Mock callback processing user info:', userInfo);

      // Store userInfo in the request for the mock strategy
      req.body = {
        email: userInfo.email,
        mockAuth: 'true',
        userInfo: userInfo
      };

      // Authenticate using mock strategy with proper session handling
      passport.authenticate('mock-oidc', async (err: any, user: any) => {
        if (err) {
          console.error('Mock authentication error:', err);
          return res.redirect('/auth/login?error=server_error');
        }

        if (!user) {
          console.error('Mock authentication failed: no user returned');
          return res.redirect('/auth/login?error=authentication_failed');
        }

        console.log('🎭 Mock authentication successful, logging in user:', user.email);
        console.log('🎭 Session ID before login:', req.sessionID);

        req.logIn(user, async (err) => {
          if (err) {
            console.error('Mock login error:', err);
            return res.redirect('/auth/login?error=login_failed');
          }

          console.log('🎭 User logged in successfully, session ID after login:', req.sessionID);
          console.log('🎭 Session passport data:', (req.session as any).passport);

          // Update last login
          await this.authService.updateLastLogin(user.id);

          // Get the return URL from session or use default
          const returnTo = (req.session as any).returnTo || '/dashboard';
          const fullReturnUrl = returnTo.startsWith('http') ? returnTo : `${process.env.FRONTEND_URL || 'https://front.localhost'}${returnTo}`;
          delete (req.session as any).returnTo;

          console.log('🎭 Redirecting to:', fullReturnUrl);
          return res.redirect(fullReturnUrl);
        });
      })(req, res, next);
    } catch (error) {
      console.error('Mock callback error:', error);
      res.redirect('/auth/login?error=callback_processing_failed');
      return;
    }
  };
}
