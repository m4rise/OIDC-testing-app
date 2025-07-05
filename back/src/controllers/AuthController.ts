import { Request, Response } from 'express';
import { AuthService } from '../services/AuthService';
import { TokenInfo } from '../middleware/security';
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
    console.log('🎭 Storing returnTo in session:', returnTo);

    if (req.session) {
      (req.session as any).returnTo = returnTo;
      console.log('🎭 Session ID when storing returnTo:', req.sessionID);
    }

    // Use standard passport authenticate
    return passport.authenticate('oidc', {
      scope: 'openid profile email'
    })(req, res, next);
  };

  // Handle OIDC callback using standard passport authenticate
  callback = (req: Request, res: Response, next: Function) => {
    return passport.authenticate('oidc', {
      successRedirect: this.getSuccessRedirect(req),
      failureRedirect: this.getFailureRedirect(),
      failureFlash: false
    })(req, res, next);
  };

  private getSuccessRedirect(req: Request): string {
    const returnTo = (req.session as any)?.returnTo || '/';
    const frontendUrl = UrlHelper.getFrontendUrl();
    console.log('🎭 Redirecting to success URL:', `${frontendUrl}${returnTo}`);
    return `${frontendUrl}${returnTo}`;
  }

  private getFailureRedirect(): string {
    const frontendUrl = UrlHelper.getFrontendUrl();
    return `${frontendUrl}/login?error=auth_failed`;
  }

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

  // Get token status and expiration information
  getTokenStatus = async (req: Request, res: Response) => {
    try {
      const isAuthenticated = !!(req.session as any)?.passport?.user || !!req.user;
      if (!isAuthenticated) {
        res.status(401).json({ error: 'Not authenticated' });
        return;
      }

      const tokenInfo: TokenInfo | undefined = (req.session as any).tokenInfo;

      if (!tokenInfo) {
        res.json({
          hasToken: false,
          message: 'No token information available'
        });
        return;
      }

      const now = Date.now();
      const timeUntilExpiry = tokenInfo.tokenExpiry ? tokenInfo.tokenExpiry - now : null;
      const timeUntilRefreshExpiry = tokenInfo.refreshExpiry ? tokenInfo.refreshExpiry - now : null;

      res.json({
        hasToken: true,
        hasAccessToken: !!tokenInfo.accessToken,
        hasIdToken: !!tokenInfo.idToken,
        hasRefreshToken: !!tokenInfo.refreshToken,
        tokenExpiry: tokenInfo.tokenExpiry ? new Date(tokenInfo.tokenExpiry).toISOString() : null,
        refreshExpiry: tokenInfo.refreshExpiry ? new Date(tokenInfo.refreshExpiry).toISOString() : null,
        isTokenExpired: timeUntilExpiry ? timeUntilExpiry <= 0 : null,
        isRefreshExpired: timeUntilRefreshExpiry ? timeUntilRefreshExpiry <= 0 : null,
        timeUntilExpiry: timeUntilExpiry && timeUntilExpiry > 0 ? Math.round(timeUntilExpiry / 1000) : null,
        timeUntilRefreshExpiry: timeUntilRefreshExpiry && timeUntilRefreshExpiry > 0 ? Math.round(timeUntilRefreshExpiry / 1000) : null,
        lastRefresh: tokenInfo.lastRefresh ? new Date(tokenInfo.lastRefresh).toISOString() : null
      });
    } catch (error) {
      console.error('Token status error:', error);
      res.status(500).json({ error: 'Failed to get token status' });
    }
  };

  // Manually refresh token
  refreshToken = async (req: Request, res: Response) => {
    try {
      const isAuthenticated = !!(req.session as any)?.passport?.user || !!req.user;
      if (!isAuthenticated) {
        res.status(401).json({ error: 'Not authenticated' });
        return;
      }

      const tokenInfo: TokenInfo | undefined = (req.session as any).tokenInfo;

      if (!tokenInfo || !tokenInfo.refreshToken) {
        res.status(400).json({
          error: 'No refresh token available',
          message: 'Cannot refresh token without refresh token'
        });
        return;
      }

      const now = Date.now();
      if (tokenInfo.refreshExpiry && now > tokenInfo.refreshExpiry) {
        res.status(400).json({
          error: 'Refresh token expired',
          message: 'Refresh token has expired, please log in again'
        });
        return;
      }

      // Attempt to refresh the token using the same logic as session security middleware
      const useMockOIDC = process.env.NODE_ENV === 'development' && process.env.USE_MOCK_OIDC === 'true';

      try {
        let refreshed = false;
        if (useMockOIDC) {
          refreshed = await this.refreshMockTokens(req, tokenInfo);
        } else {
          refreshed = await this.refreshRealTokens(req, tokenInfo);
        }

        if (refreshed) {
          const updatedTokenInfo: TokenInfo = (req.session as any).tokenInfo;
          res.json({
            success: true,
            message: 'Token refreshed successfully',
            tokenExpiry: updatedTokenInfo.tokenExpiry ? new Date(updatedTokenInfo.tokenExpiry).toISOString() : null,
            refreshedAt: new Date().toISOString()
          });
        } else {
          res.status(400).json({
            error: 'Token refresh failed',
            message: 'Unable to refresh token, please log in again'
          });
        }
      } catch (refreshError) {
        console.error('Token refresh error:', refreshError);
        res.status(500).json({
          error: 'Token refresh failed',
          message: 'Token refresh encountered an error'
        });
      }
    } catch (error) {
      console.error('Refresh token error:', error);
      res.status(500).json({ error: 'Failed to refresh token' });
    }
  };

  // Test endpoint that doesn't require authentication
  getTokenStatusPublic = async (req: Request, res: Response) => {
    try {
      const isAuthenticated = !!(req.session as any)?.passport?.user || !!req.user;
      const hasSession = !!req.session;
      const sessionId = req.sessionID;

      if (!isAuthenticated) {
        res.json({
          status: 'not_authenticated',
          message: 'You need to log in first to view token status',
          isAuthenticated: false,
          hasSession: hasSession,
          sessionId: sessionId ? 'present' : 'none',
          helpUrl: '/api/auth/login'
        });
        return;
      }

      // If authenticated, return the same as getTokenStatus
      const tokenInfo: TokenInfo | undefined = (req.session as any).tokenInfo;

      if (!tokenInfo) {
        res.json({
          status: 'authenticated_no_tokens',
          message: 'Authenticated but no token information available',
          isAuthenticated: true,
          hasToken: false,
          hasSession: hasSession,
          sessionId: sessionId ? 'present' : 'none'
        });
        return;
      }

      const now = Date.now();
      const timeUntilExpiry = tokenInfo.tokenExpiry ? tokenInfo.tokenExpiry - now : null;
      const timeUntilRefreshExpiry = tokenInfo.refreshExpiry ? tokenInfo.refreshExpiry - now : null;

      res.json({
        status: 'authenticated_with_tokens',
        isAuthenticated: true,
        hasToken: true,
        hasAccessToken: !!tokenInfo.accessToken,
        hasIdToken: !!tokenInfo.idToken,
        hasRefreshToken: !!tokenInfo.refreshToken,
        tokenExpiry: tokenInfo.tokenExpiry ? new Date(tokenInfo.tokenExpiry).toISOString() : null,
        refreshExpiry: tokenInfo.refreshExpiry ? new Date(tokenInfo.refreshExpiry).toISOString() : null,
        isTokenExpired: timeUntilExpiry ? timeUntilExpiry <= 0 : null,
        isRefreshExpired: timeUntilRefreshExpiry ? timeUntilRefreshExpiry <= 0 : null,
        timeUntilExpiry: timeUntilExpiry && timeUntilExpiry > 0 ? Math.round(timeUntilExpiry / 1000) : null,
        timeUntilRefreshExpiry: timeUntilRefreshExpiry && timeUntilRefreshExpiry > 0 ? Math.round(timeUntilRefreshExpiry / 1000) : null,
        lastRefresh: tokenInfo.lastRefresh ? new Date(tokenInfo.lastRefresh).toISOString() : null,
        hasSession: hasSession,
        sessionId: sessionId ? 'present' : 'none'
      });
    } catch (error) {
      console.error('Token status public error:', error);
      res.status(500).json({
        status: 'error',
        error: 'Failed to get token status',
        message: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  };

  // Debug endpoint to check session contents
  getSessionDebug = async (req: Request, res: Response) => {
    try {
      const isAuthenticated = !!(req.session as any)?.passport?.user || !!req.user;
      const sessionData = {
        sessionId: req.sessionID,
        isAuthenticated,
        user: req.user ? {
          id: (req.user as any).id,
          nni: (req.user as any).nni,
          email: (req.user as any).email,
          firstName: (req.user as any).firstName,
          lastName: (req.user as any).lastName,
          role: (req.user as any).role
        } : null,
        sessionKeys: Object.keys(req.session),
        tokenInfo: (req.session as any).tokenInfo || null,
        rawSession: process.env.NODE_ENV === 'development' ? req.session : 'hidden_in_production'
      };

      res.json(sessionData);
    } catch (error) {
      console.error('Session debug error:', error);
      res.status(500).json({ error: 'Failed to get session debug info' });
    }
  };

  // Handle authentication failure
  failure = (req: Request, res: Response) => {
    console.log('❌ Authentication failure accessed');

    // Clear any session data
    delete (req.session as any).oidcState;
    delete (req.session as any).oidcNonce;

    // Handle both API and browser requests
    if (req.headers.accept?.includes('application/json')) {
      res.status(401).json({
        error: 'Authentication failed',
        message: 'Login was unsuccessful'
      });
    } else {
      const frontendUrl = UrlHelper.getFrontendUrl();
      res.redirect(`${frontendUrl}/login?error=auth_failed`);
    }
  };

  // Helper method for refreshing real OIDC tokens
  private async refreshRealTokens(req: Request, tokenInfo: TokenInfo): Promise<boolean> {
    try {
      const tokenEndpoint = `${process.env.OIDC_ISSUER}/token`;

      const response = await fetch(tokenEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': `Basic ${Buffer.from(`${process.env.OIDC_CLIENT_ID}:${process.env.OIDC_CLIENT_SECRET}`).toString('base64')}`
        },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: tokenInfo.refreshToken!,
          scope: 'openid profile email'
        })
      });

      if (!response.ok) {
        console.error('Token refresh failed:', response.status, response.statusText);
        return false;
      }

      const tokens = await response.json();

      // Update token info in session
      const updatedTokenInfo: TokenInfo = {
        ...tokenInfo,
        accessToken: tokens.access_token,
        idToken: tokens.id_token,
        refreshToken: tokens.refresh_token || tokenInfo.refreshToken,
        expiresAt: Date.now() + (tokens.expires_in * 1000),
        lastRefresh: Date.now()
      };

      // Decode ID token to get expiration
      if (tokens.id_token) {
        const idTokenPayload = JSON.parse(Buffer.from(tokens.id_token.split('.')[1], 'base64').toString());
        updatedTokenInfo.tokenExpiry = idTokenPayload.exp * 1000;
      }

      (req.session as any).tokenInfo = updatedTokenInfo;

      return true;
    } catch (error) {
      console.error('Real token refresh error:', error);
      return false;
    }
  }

  // Helper method for refreshing mock OIDC tokens
  private async refreshMockTokens(req: Request, tokenInfo: TokenInfo): Promise<boolean> {
    try {
      // Use internal URL for server-to-server communication
      const tokenEndpoint = UrlHelper.getApiEndpointUrl('token', 'internal');

      const response = await fetch(tokenEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: tokenInfo.refreshToken!,
          client_id: process.env.OIDC_CLIENT_ID || 'mock-client-id',
          client_secret: process.env.OIDC_CLIENT_SECRET || 'mock-client-secret'
        })
      });

      if (!response.ok) {
        console.error('Mock token refresh failed:', response.status, response.statusText);
        return false;
      }

      const tokens = await response.json();

      // Update token info in session
      const updatedTokenInfo: TokenInfo = {
        ...tokenInfo,
        accessToken: tokens.access_token,
        idToken: tokens.id_token,
        refreshToken: tokens.refresh_token || tokenInfo.refreshToken,
        expiresAt: Date.now() + (tokens.expires_in * 1000),
        lastRefresh: Date.now()
      };

      // Decode ID token to get expiration
      if (tokens.id_token) {
        const idTokenPayload = JSON.parse(Buffer.from(tokens.id_token.split('.')[1], 'base64').toString());
        updatedTokenInfo.tokenExpiry = idTokenPayload.exp * 1000;
      }

      (req.session as any).tokenInfo = updatedTokenInfo;

      return true;
    } catch (error) {
      console.error('Mock token refresh error:', error);
      return false;
    }
  }
}
