import { Request, Response, NextFunction } from 'express';

/**
 * Simple session security middleware
 * Uses Express session cookie maxAge for expiration - no complex token handling
 */
export const sessionSecurity = async (req: Request, res: Response, next: NextFunction) => {
  try {
    // Only check authenticated users
    if (req.isAuthenticated() && req.session && req.session.cookie) {
      const now = Date.now();
      const cookieExpires = req.session.cookie.expires;

      // Check if session cookie has expired
      if (cookieExpires && now > cookieExpires.getTime()) {
        console.log('🔒 Session cookie expired - forcing logout');

        // Force logout and session cleanup
        req.logout((err) => {
          if (err) console.error('Logout error:', err);

          // Destroy the session completely
          req.session.destroy((destroyErr) => {
            if (destroyErr) console.error('Session destroy error:', destroyErr);

            // Handle response based on request type
            if (req.xhr || req.headers.accept?.includes('application/json')) {
              // API request - return 401
              res.status(401).json({
                error: 'session_expired',
                message: 'Session has expired. Please log in again.',
                requiresReauth: true
              });
            } else {
              // Browser request - redirect to login
              const returnTo = encodeURIComponent(req.originalUrl);
              res.redirect(`/api/auth/login?reason=expired&returnTo=${returnTo}`);
            }
          });
        });
        return;
      }
    }

    // Continue processing
    next();
  } catch (error) {
    console.error('Session security middleware error:', error);
    next(error);
  }
};

