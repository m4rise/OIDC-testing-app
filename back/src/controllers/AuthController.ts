import { Request, Response } from 'express';
import { AuthService } from '../services/AuthService';
import { UrlHelper } from '../utils/urlHelper';
import passport from '../config/auth';

export class AuthController {
  private authService: AuthService;

  constructor() {
    this.authService = new AuthService();
  }

  // Initiate OIDC login using standard passport authenticate
  login = (req: Request, res: Response, next: Function) => {
    // Store returnTo URL in session
    const returnTo = req.query.returnTo as string || '/';

    if (req.session) {
      (req.session as any).returnTo = returnTo;
    }

    // Use standard passport authenticate
    return passport.authenticate('oidc')(req, res, next);
  };

  // Handle OIDC callback using standard passport authenticate with proper callback
  callback = (req: Request, res: Response, next: Function) => {
    return passport.authenticate('oidc', (err: any, user: any, info: any) => {
      if (err) {
        console.error('❌ Authentication error:', err);
        return res.redirect(this.getFailureRedirect());
      }

      if (!user) {
        console.error('❌ Authentication failed: no user returned');
        return res.redirect(this.getFailureRedirect());
      }

      // Log the user in (this triggers serializeUser)
      req.logIn(user, (loginErr) => {
        if (loginErr) {
          console.error('❌ Login error:', loginErr);
          return res.redirect(this.getFailureRedirect());
        }

        // Store JWT expiry in session after passport login completes
        // This ensures it persists after session serialization/deserialization
        if ((user as any).tempJwtExpiry) {
          (req.session as any).jwtExpiry = (user as any).tempJwtExpiry;
          console.log('🔒 Stored JWT expiry in session after login:', new Date((user as any).tempJwtExpiry).toISOString());
          // Clean up temporary property
          delete (user as any).tempJwtExpiry;
        }

        const successUrl = this.getSuccessRedirect(req);
        return res.redirect(successUrl);
      });
    })(req, res, next);
  };

  // Get current session info
  getSession = async (req: Request, res: Response) => {
    try {
      const sessionInfo = await this.authService.getSessionInfo(req);
      res.json(sessionInfo);
    } catch (error) {
      console.error('Session info error:', error);
      res.status(500).json({ error: 'Failed to get session info' });
    }
  };

  // Check authentication status
  checkAuth = (req: Request, res: Response) => {
    const isAuthenticated = !!(req.session as any)?.passport?.user || !!req.user;
    res.json({
      isAuthenticated,
      user: req.user || null
    });
  };

  // Logout user
  logout = (req: Request, res: Response): void => {
    const isAuthenticated = !!(req.session as any)?.passport?.user || !!req.user;
    const userEmail = req.user ? (req.user as any).email : 'anonymous';

    req.logout((err) => {
      if (err) {
        console.error('Logout error:', err);
        res.status(500).json({ error: 'Logout failed' });
        return;
      }

      // Destroy session
      req.session.destroy((err) => {
        if (err) {
          console.error('Session destruction error:', err);
          res.status(500).json({ error: 'Session cleanup failed' });
          return;
        }

        console.log(`👋 User ${userEmail} logged out successfully`);

        // Handle both API and browser requests
        if (req.headers.accept?.includes('application/json')) {
          res.json({
            message: 'Logged out successfully',
            wasAuthenticated: isAuthenticated
          });
        } else {
          res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?logged_out=true`);
        }
      });
    });
  };

  // Debug endpoint to check session contents
  getSessionDebug = async (req: Request, res: Response) => {
    try {
      const isAuthenticated = !!(req.session as any)?.passport?.user || !!req.user;
      const sessionData = {
        sessionId: req.sessionID,
        isAuthenticated,
        user: req.user ?? null,
        sessionKeys: Object.keys(req.session),
        rawSession: process.env.NODE_ENV === 'development' ? req.session : 'hidden_in_production'
      };

      res.json(sessionData);
    } catch (error) {
      console.error('Session debug error:', error);
      res.status(500).json({ error: 'Failed to get session debug info' });
    }
  };

  private getSuccessRedirect(req: Request): string {
    const returnTo = (req.session as any)?.returnTo || '/';
    const frontendUrl = UrlHelper.getFrontendUrl();
    return `${frontendUrl}${returnTo}`;
  }

  private getFailureRedirect(): string {
    const frontendUrl = UrlHelper.getFrontendUrl();
    return `${frontendUrl}/login?error=auth_failed`;
  }
}
