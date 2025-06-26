import { Request, Response, NextFunction } from 'express';

/**
 * Session security middleware
 * Adds additional checks for session integrity and security
 */
export const sessionSecurity = (req: Request, res: Response, next: NextFunction) => {
  // Check for session fixation attempts
  if (req.session && req.sessionID) {
    const sessionAge = Date.now() - (req.session as any).createdAt || 0;
    const maxSessionAge = 24 * 60 * 60 * 1000; // 24 hours

    // Regenerate session ID periodically for security
    if (sessionAge > maxSessionAge && req.isAuthenticated()) {
      console.log('🔄 Regenerating session ID for security');
      req.session.regenerate((err) => {
        if (err) {
          console.error('Session regeneration failed:', err);
        }
        next();
      });
      return;
    }
  }

  next();
};
