import { Request, Response, NextFunction } from 'express';
import { User, UserRole } from '../entities/User';

// Helper function to check authentication and return user or null (without sending response)
const checkAuthAndGetUser = (req: Request): User | null => {
  if (!req.isAuthenticated() || !req.user) {
    return null;
  }
  return req.user as User;
};

// Helper function to send authentication error response
const sendAuthError = (res: Response): void => {
  res.status(401).json({
    error: 'Authentication required',
    message: 'You must be logged in to access this resource'
  });
};

// Middleware to ensure user is authenticated
export const requireAuth = (req: Request, res: Response, next: NextFunction): void => {
  const user = checkAuthAndGetUser(req);
  if (!user) {
    sendAuthError(res);
    return;
  }
  next();
};

// Middleware to ensure user has specific role (assumes user is already authenticated)
export const requireRole = (roles: UserRole | UserRole[]) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const user = req.user as User; // Assumes user is already authenticated

    const userRoles = Array.isArray(roles) ? roles : [roles];

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

// Middleware to ensure user has specific permission (assumes user is already authenticated)
export const requirePermission = (permission: string) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const user = req.user as User; // User instance with hasPermission() method

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

// Middleware to ensure user account is active (assumes user is already authenticated)
export const requireActiveAccount = (req: Request, res: Response, next: NextFunction): void => {
  const user = req.user as User; // Assumes user is already authenticated

  if (!user.isActive) {
    res.status(403).json({
      error: 'Account inactive',
      message: 'Your account has been deactivated. Please contact an administrator.'
    });
    return;
  }

  next();
};

// Convenience middleware combinations for common use cases
export const requireAuthenticatedUser = [requireAuth];
export const requireAuthenticatedActiveUser = [requireAuth, requireActiveAccount];
export const requireAdmin = [requireAuth, requireActiveAccount, requireRole(UserRole.ADMIN)];
export const requireModerator = [requireAuth, requireActiveAccount, requireRole([UserRole.ADMIN, UserRole.MODERATOR])];
export const requireActiveUserWithRole = (roles: UserRole | UserRole[]) => [
  requireAuth,
  requireActiveAccount,
  requireRole(roles)
];
export const requireActiveUserWithPermission = (permission: string) => [
  requireAuth,
  requireActiveAccount,
  requirePermission(permission)
];
