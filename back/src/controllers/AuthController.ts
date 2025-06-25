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
    (req.session as any).returnTo = req.query.returnTo as string || '/';

    passport.authenticate('oidc', {
      scope: 'openid profile email'
    })(req, res, next);
  };

  // Handle OIDC callback
  callback = (req: Request, res: Response, next: Function) => {
    passport.authenticate('oidc', {
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
      const sessionInfo = await this.authService.getSessionInfo(req);
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
}
