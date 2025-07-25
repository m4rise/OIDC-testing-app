import { inject } from '@angular/core';
import { Router, type CanActivateFn } from '@angular/router';
import { map, take, from } from 'rxjs';

import { AuthService } from '../services/auth.service';

/**
 * Factory function to create permission-based guards
 * Usage: canActivate: [createPermissionGuard('api:user:read:*')]
 */
export function createPermissionGuard(requiredPermission: string): CanActivateFn {
  return (route, state) => {
    const authService = inject(AuthService);
    const router = inject(Router);

    // Initialize auth service if not already initialized
    if (!authService.isInitialized()) {
      return from(authService.initialize()).pipe(
        take(1),
        map(() => checkPermissionAccess(authService, router, requiredPermission))
      );
    }

    return checkPermissionAccess(authService, router, requiredPermission);
  };
}

/**
 * Helper function to check permission access
 */
function checkPermissionAccess(
  authService: AuthService,
  router: Router,
  requiredPermission: string
): boolean {
  // First check if user is authenticated
  if (!authService.isAuthenticated()) {
    console.log('PermissionGuard: User not authenticated, triggering SSO redirect');
    authService.handleUnauthenticatedUser();
    return false;
  }

  // Check if user has required permission
  if (!authService.hasPermission(requiredPermission)) {
    console.log('PermissionGuard: User lacks required permission:', requiredPermission);
    router.navigate(['/dashboard']);
    return false;
  }

  return true;
}

/**
 * Convenience guards for common permissions
 */
export const canReadUsers = createPermissionGuard('api:user:read:*');
export const canWriteUsers = createPermissionGuard('api:user:write:*');
export const canDeleteUsers = createPermissionGuard('api:user:delete:*');
export const canAccessAdmin = createPermissionGuard('route:admin');
