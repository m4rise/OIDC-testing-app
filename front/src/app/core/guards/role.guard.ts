import { inject } from '@angular/core';
import { Router, type CanActivateFn } from '@angular/router';
import { map, take, from } from 'rxjs';

import { AuthService } from '../services/auth.service';

/**
 * Factory function to create role-based guards
 * Usage: canActivate: [createRoleGuard(['admin', 'moderator'])]
 */
export function createRoleGuard(requiredRoles: string[]): CanActivateFn {
  return (route, state) => {
    const authService = inject(AuthService);
    const router = inject(Router);

    // Initialize auth service if not already initialized
    if (!authService.isInitialized()) {
      return from(authService.initialize()).pipe(
        take(1),
        map(() => checkRoleAccess(authService, router, requiredRoles))
      );
    }

    return checkRoleAccess(authService, router, requiredRoles);
  };
}

/**
 * Helper function to check role access
 */
function checkRoleAccess(
  authService: AuthService,
  router: Router,
  requiredRoles: string[]
): boolean {
  // First check if user is authenticated
  if (!authService.isAuthenticated()) {
    console.log('RoleGuard: User not authenticated, triggering SSO redirect');
    authService.handleUnauthenticatedUser();
    return false;
  }

  // Check if user has required role
  if (!authService.hasRole(requiredRoles)) {
    console.log('RoleGuard: User lacks required roles:', requiredRoles);
    router.navigate(['/dashboard']);
    return false;
  }

  return true;
}

/**
 * Predefined role guards for common use cases
 */
export const adminGuard: CanActivateFn = createRoleGuard(['admin']);
export const moderatorGuard: CanActivateFn = createRoleGuard(['admin', 'moderator']);
