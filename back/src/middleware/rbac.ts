import { Request, Response, NextFunction } from 'express';

// Helper functions
export const isAuthenticated = (req: Request): boolean => {
  return !!req.user && req.isAuthenticated();
};

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

export const matchesPermission = (userPermission: string, requiredPermission: string): boolean => {
  const userParts = userPermission.split(':');
  const reqParts = requiredPermission.split(':');

  // Shorter permissions cover longer ones: "api:user" covers "api:user:read:self"
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

export function requirePermission(requiredPermission: string) {
  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      if (!isAuthenticated(req) || !req.user) {
        sendAuthRequired(res);
        return;
      }

      const user = req.user as any; // Lightweight user from passport deserialization
      const userPermissions: string[] = user.permissions || [];

      // Check if user has the required permission
      const hasPermission = userPermissions.some(permission =>
        matchesPermission(permission, requiredPermission)
      );

      if (!hasPermission) {
        console.log(`❌ Permission denied: User ${user.email} lacks ${requiredPermission}`);
        sendInsufficientPermissions(res, requiredPermission);
        return;
      }

      console.log(`✅ Permission granted: ${requiredPermission} for ${user.email}`);
      next();
    } catch (error) {
      console.error('RBAC middleware error:', error);
      res.status(500).json({ error: 'Permission check failed' });
    }
  };
}

export function requireRole(roleName: string) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!isAuthenticated(req) || !req.user) {
      sendAuthRequired(res);
      return;
    }

    const user = req.user as any; // Lightweight user from passport deserialization
    const userRoles: string[] = user.roles || [];

    if (!userRoles.includes(roleName)) {
      sendInsufficientRole(res, roleName);
      return;
    }

    next();
  };
}
