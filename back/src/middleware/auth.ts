import { Request, Response, NextFunction } from 'express';
import { isAuthenticated } from './rbac';

// Simple authentication middleware - just checks if user is logged in
export const requireAuth = (req: Request, res: Response, next: NextFunction): void => {
  if (!isAuthenticated(req)) {
    res.status(401).json({
      error: 'Authentication required',
      message: 'You must be logged in to access this resource'
    });
    return;
  }
  next();
};

// Account status middleware
export const requireActiveAccount = (req: Request, res: Response, next: NextFunction): void => {
  const user = req.user as any;
  if (user && !user.isActive) {
    res.status(403).json({
      error: 'Account inactive',
      message: 'Your account has been deactivated. Please contact an administrator.'
    });
    return;
  }
  next();
};

// Convenience combinations
export const requireAuthenticatedActiveUser = [requireAuth, requireActiveAccount];
