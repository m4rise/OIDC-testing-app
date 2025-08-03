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
 *
 * Principe: Les permissions plus courtes couvrent les plus longues
 * + support des wildcards bidirectionnels
 *
 * Exemples:
 * - "api:user" couvre "api:user:read:self" (hiérarchique)
 * - "api:*" couvre "api:user:read:self" (wildcard user)
 * - "api:user:read:self" match "api:*:read:*" (wildcard requis)
 * - "api:user:read:self:extra" match "api:*:read:*" (wildcard extensible)
 */
export const matchesPermission = (userPermission: string, requiredPermission: string): boolean => {
  const userParts = userPermission.split(':');
  const reqParts = requiredPermission.split(':');

  // On compare sur la longueur la plus courte
  const minLength = Math.min(userParts.length, reqParts.length);

  for (let i = 0; i < minLength; i++) {
    if (userParts[i] !== reqParts[i] && userParts[i] !== '*' && reqParts[i] !== '*') {
      return false;
    }
  }

  // Si user est plus court ou égal, c'est OK (principe hiérarchique)
  if (userParts.length <= reqParts.length) {
    return true;
  }

  // Si user est plus long ET que required se termine par un wildcard,
  // alors user peut être plus spécifique
  if (reqParts[reqParts.length - 1] === '*') {
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
 * Supports both hierarchical permissions and wildcard patterns
 */
export function checkPermission(requiredPermission: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = getAuthenticatedUser(req);

      if (!user) {
        console.log(`❌ Permission denied: No authenticated user for ${requiredPermission}`);
        sendInsufficientPermissions(res, requiredPermission);
        return;
      }

      // Get user permissions from roles and direct permissions
      const userPermissions: string[] = [];

      // Add permissions from roles
      if (user.roles && Array.isArray(user.roles)) {
        user.roles.forEach((role: any) => {
          if (role.permissions && Array.isArray(role.permissions)) {
            role.permissions.forEach((perm: any) => {
              if (typeof perm === 'string') {
                userPermissions.push(perm);
              } else if (perm.name) {
                userPermissions.push(perm.name);
              }
            });
          }
        });
      }

      // Add direct permissions (if any)
      if (user.permissions && Array.isArray(user.permissions)) {
        user.permissions.forEach((perm: any) => {
          if (typeof perm === 'string') {
            userPermissions.push(perm);
          } else if (perm.name) {
            userPermissions.push(perm.name);
          }
        });
      }

      // Check if user has the required permission
      const hasPermission = userPermissions.some(userPerm =>
        matchesPermission(userPerm, requiredPermission)
      );

      if (!hasPermission) {
        console.log(`❌ Permission denied: User ${user.email} lacks ${requiredPermission}`);
        console.log(`   User permissions: [${userPermissions.join(', ')}]`);
        sendInsufficientPermissions(res, requiredPermission);
        return;
      }

      console.log(`✅ Permission granted: ${requiredPermission} for ${user.email}`);
      next();
    } catch (error) {
      console.error('Permission check error:', error);
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
