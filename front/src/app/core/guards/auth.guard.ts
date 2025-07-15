import { inject } from '@angular/core';
import { type CanActivateFn } from '@angular/router';
import { map, take, from } from 'rxjs';

import { AuthService } from '../services/auth.service';

/**
 * Basic authentication guard - only checks if user is authenticated
 * Use role-specific guards from role.guard.ts for permission-based access
 */
export const authGuard: CanActivateFn = (route, state) => {
  const authService = inject(AuthService);

  // Initialize auth service if not already initialized
  if (!authService.isInitialized()) {
    console.log('AuthGuard: Initializing auth service...');

    return from(authService.initialize()).pipe(
      take(1),
      map(() => {
        const isAuthenticated = authService.isAuthenticated();
        console.log('AuthGuard: Authentication check after init:', isAuthenticated);

        if (!isAuthenticated) {
          console.log('AuthGuard: User not authenticated, triggering SSO redirect');
          authService.handleUnauthenticatedUser();
          return false;
        }

        return true;
      })
    );
  }

  // If already initialized, check authentication
  if (!authService.isAuthenticated()) {
    console.log('AuthGuard: User not authenticated, triggering SSO redirect');
    authService.handleUnauthenticatedUser();
    return false;
  }

  return true;
};
