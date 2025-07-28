import { Request, Response, NextFunction } from 'express';
import { config } from '../config/environment';

/**
 * Session security middleware that enforces JWT token expiration
 *
 * This middleware implements a hybrid approach:
 * 1. First checks for actual JWT expiry stored in session (if available)
 * 2. Falls back to lastLoginAt + default JWT lifetime if JWT exp not available
 *
 * This ensures the session cannot outlive the JWT token regardless of rolling sessions
 */
export const sessionSecurity = (req: Request, res: Response, next: NextFunction): void => {
  // Only check token expiry for authenticated users
  if (!req.isAuthenticated() || !req.user) {
    return next();
  }

  const user = req.user;
  const session = req.session;

  try {
    let tokenExpired = false;
    let expiredAt: Date | null = null;

    // Hybrid approach: Check for actual JWT expiry first, then fallback
    if (session.jwtExpiry) {
      // Use actual JWT expiry stored in session
      const jwtExpiry = new Date(session.jwtExpiry);
      if (Date.now() > jwtExpiry.getTime()) {
        tokenExpired = true;
        expiredAt = jwtExpiry;
      }
      console.log(`🔒 Using actual JWT expiry from session: ${jwtExpiry.toISOString()}, expired: ${tokenExpired}`);
    } else if (user.lastLoginAt) {
      // Fallback: Use lastLoginAt + configured session max age
      // Note: For dev interceptor, JWT expiry is controlled by DEV_JWT_EXPIRY_MINUTES
      const defaultJwtLifetimeMs = config.session.maxAgeMinutes * 60 * 1000; // Convert minutes to milliseconds
      const calculatedExpiry = new Date(user.lastLoginAt.getTime() + defaultJwtLifetimeMs);

      if (Date.now() > calculatedExpiry.getTime()) {
        tokenExpired = true;
        expiredAt = calculatedExpiry;
      }
      console.log(`🔒 Using fallback expiry calculation: lastLogin=${user.lastLoginAt.toISOString()}, calculatedExpiry=${calculatedExpiry.toISOString()}, expired=${tokenExpired}`);
    }

    if (tokenExpired && expiredAt) {
      console.log(`⏰ Session expired for user ${user.email} at ${expiredAt.toISOString()}`);

      // Force logout by destroying session
      req.logout((logoutErr) => {
        if (logoutErr) {
          console.error('❌ Error during forced logout:', logoutErr);
        }

        req.session.destroy((sessionErr) => {
          if (sessionErr) {
            console.error('❌ Error destroying session:', sessionErr);
          }

          // Return 401 to trigger frontend re-authentication
          res.status(401).json({
            error: 'session_expired',
            message: 'Your session has expired. Please log in again.',
            expiredAt: expiredAt.toISOString()
          });
        });
      });
      return;
    }

    // Session is valid, continue
    next();

  } catch (error) {
    console.error('❌ Error in session security middleware:', error);
    // Don't block the request on middleware errors, but log them
    next();
  }
};
