import { Request, Response, NextFunction } from 'express';
import { User, UserRole } from '../entities/User';

// Extend the Express Request interface to include user
declare global {
  namespace Express {
    interface User {
      id: string;
      email: string;
      firstName: string;
      lastName: string;
      role: UserRole;
      isActive: boolean;
      hasPermission: (permission: string) => boolean;
    }
  }
}

// Middleware to ensure user is authenticated
export const requireAuth = (req: Request, res: Response, next: NextFunction): void => {
  if (req.isAuthenticated() && req.user) {
    return next();
  }

  res.status(401).json({
    error: 'Authentication required',
    message: 'You must be logged in to access this resource'
  });
};

// Middleware to ensure user has specific role
export const requireRole = (roles: UserRole | UserRole[]) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.isAuthenticated() || !req.user) {
      res.status(401).json({
        error: 'Authentication required',
        message: 'You must be logged in to access this resource'
      });
      return;
    }

    const userRoles = Array.isArray(roles) ? roles : [roles];
    const user = req.user as User;

    if (!userRoles.includes(user.role)) {
      res.status(403).json({
        error: 'Insufficient permissions',
        message: 'You do not have the required role to access this resource'
      });
      return;
    }

    next();
  };
};

// Middleware to ensure user has specific permission
export const requirePermission = (permission: string) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.isAuthenticated() || !req.user) {
      res.status(401).json({
        error: 'Authentication required',
        message: 'You must be logged in to access this resource'
      });
      return;
    }

    const user = req.user as User;

    if (!user.hasPermission(permission)) {
      res.status(403).json({
        error: 'Insufficient permissions',
        message: `You do not have the '${permission}' permission to access this resource`
      });
      return;
    }

    next();
  };
};

// Middleware to ensure user account is active
export const requireActiveAccount = (req: Request, res: Response, next: NextFunction): void => {
  if (!req.isAuthenticated() || !req.user) {
    res.status(401).json({
      error: 'Authentication required',
      message: 'You must be logged in to access this resource'
    });
    return;
  }

  const user = req.user as User;

  if (!user.isActive) {
    res.status(403).json({
      error: 'Account inactive',
      message: 'Your account has been deactivated. Please contact an administrator.'
    });
    return;
  }

  next();
};
