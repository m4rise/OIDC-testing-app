import { Request, Response, NextFunction } from 'express';

// ===========================
// UTILITY FUNCTIONS
// ===========================

/**
 * Get the authenticated user from request (with type safety)
 */
export const getAuthenticatedUser = (req: Request) => {
  return req.isAuthenticated() ? req.user || null : null;
};

/**
 * Check if a user permission matches a required permission (supports wildcards)
 * Shorter permissions cover longer ones: "api:user" covers "api:user:read:self"
 */
export const matchesPermission = (userPermission: string, requiredPermission: string): boolean => {
  const userParts = userPermission.split(':');
  const reqParts = requiredPermission.split(':');

  // Shorter permissions cover longer ones
  if (userParts.length <= reqParts.length) {
    for (let i = 0; i < userParts.length; i++) {
      if (userParts[i] !== reqParts[i] && userParts[i] !== '*') {
        return false;
      }
    }
    return true;
  }

  return false;
};

// ===========================
// HTTP RESPONSE HELPERS
// ===========================

export const sendAuthRequired = (res: Response): void => {
  res.status(401).json({
    error: 'Authentication required',
    message: 'You must be logged in to access this resource'
  });
};

export const sendInsufficientPermissions = (res: Response, permission: string): void => {
  res.status(403).json({
    error: 'Insufficient permissions',
    message: `You do not have the '${permission}' permission to access this resource`
  });
};

export const sendInsufficientRole = (res: Response, role: string): void => {
  res.status(403).json({
    error: 'Insufficient permissions',
    message: `You do not have the '${role}' role to access this resource`
  });
};

export const sendAccountInactive = (res: Response): void => {
  res.status(403).json({
    error: 'Account inactive',
    message: 'Your account has been deactivated. Please contact an administrator.'
  });
};

export const sendAuthorizationError = (res: Response, error: Error): void => {
  console.error('Authorization middleware error:', error);
  res.status(500).json({
    error: 'Authorization check failed',
    message: 'An error occurred while checking your permissions'
  });
};

// ===========================
// CORE MIDDLEWARE FUNCTIONS
// ===========================

/**
 * Require user to be authenticated
 */
export const requireAuth = (req: Request, res: Response, next: NextFunction) => {
  if (!req.isAuthenticated()) {
    sendAuthRequired(res);
    return;
  }
  next();
};

/**
 * Require user account to be active (assumes user is authenticated)
 */
export const requireActiveAccount = (req: Request, res: Response, next: NextFunction) => {
  const user = getAuthenticatedUser(req);
  if (!user?.isActive) {
    sendAccountInactive(res);
    return;
  }
  next();
};

/**
 * Check if user has a specific permission (assumes user is authenticated)
 */
export function checkPermission(requiredPermission: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = getAuthenticatedUser(req);
      const userPermissions = user?.permissions || [];

      const hasPermission = userPermissions.some(permission =>
        matchesPermission(permission, requiredPermission)
      );

      if (!hasPermission) {
        console.log(`❌ Permission denied: User ${user?.email} lacks ${requiredPermission}`);
        sendInsufficientPermissions(res, requiredPermission);
        return;
      }

      console.log(`✅ Permission granted: ${requiredPermission} for ${user?.email}`);
      next();
    } catch (error) {
      sendAuthorizationError(res, error as Error);
    }
  };
}

/**
 * Check if user has a specific role (assumes user is authenticated)
 */
export function checkRole(roleName: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = getAuthenticatedUser(req);
      const userRoles = user?.roles || [];

      if (!userRoles.includes(roleName)) {
        console.log(`❌ Role denied: User ${user?.email} lacks role ${roleName}`);
        sendInsufficientRole(res, roleName);
        return;
      }

      console.log(`✅ Role granted: ${roleName} for ${user?.email}`);
      next();
    } catch (error) {
      sendAuthorizationError(res, error as Error);
    }
  };
}

// ===========================
// MIDDLEWARE COMBINATIONS
// ===========================

// Basic authentication combinations
export const requireAuthenticatedUser = [requireAuth];
export const requireAuthenticatedActiveUser = [requireAuth, requireActiveAccount];

// Permission-based access control
export const requirePermission = (permission: string) => [
  requireAuth,
  checkPermission(permission)
];

export const requireActiveUserWithPermission = (permission: string) => [
  requireAuth,
  requireActiveAccount,
  checkPermission(permission)
];

// Role-based access control
export const requireRole = (roleName: string) => [
  requireAuth,
  checkRole(roleName)
];

export const requireActiveUserWithRole = (roleName: string) => [
  requireAuth,
  requireActiveAccount,
  checkRole(roleName)
];

// ===========================
// CONVENIENCE SHORTCUTS
// ===========================

// Admin access shortcuts
export const requireAdmin = requireActiveUserWithRole('admin');
export const requireModerator = requireActiveUserWithRole('moderator');

// Common permission patterns
export const requireApiAccess = (resource: string, action: string = '*') =>
  requireActiveUserWithPermission(`api:${resource}:${action}`);

export const requireRouteAccess = (route: string) =>
  requireActiveUserWithPermission(`route:${route}`);

export const requireUIAccess = (component: string) =>
  requireActiveUserWithPermission(`ui:${component}`);

// Self-access patterns (for user profile operations)
export const requireSelfAccess = (action: string) =>
  requireActiveUserWithPermission(`api:user:${action}:self`);

// Wildcard access patterns
export const requireFullUserAccess = requireActiveUserWithPermission('api:user:*');
export const requireFullApiAccess = requireActiveUserWithPermission('api:*');

// ===========================
// DEBUGGING HELPERS
// ===========================

/**
 * Middleware to log user permissions (for debugging)
 */
export const logUserPermissions = (req: Request, res: Response, next: NextFunction) => {
  const user = getAuthenticatedUser(req);
  if (user) {
    console.log(`🔍 User ${user.email} permissions:`, user.permissions);
    console.log(`🔍 User ${user.email} roles:`, user.roles);
  }
  next();
};
