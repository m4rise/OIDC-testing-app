import { inject } from '@angular/core';
import { Router, type CanActivateFn } from '@angular/router';
import { map, take, from } from 'rxjs';

import { AuthService } from '../services/auth.service';

export const authGuard: CanActivateFn = (route, state) => {
  const authService = inject(AuthService);
  const router = inject(Router);

  // Initialize auth service if not already initialized
  if (!authService.isInitialized()) {
    console.log('AuthGuard: Initializing auth service...');

    // Use the promise-based initialize method to avoid duplicate calls
    return from(authService.initialize()).pipe(
      take(1),
      map(() => {
        const isAuthenticated = authService.isAuthenticated();
        console.log('AuthGuard: Authentication check after init:', isAuthenticated);

        if (isAuthenticated) {
          // Check role-based access if specified in route data
          const requiredRoles = route.data?.['roles'] as string[];
          if (requiredRoles && !authService.hasRole(requiredRoles)) {
            console.log('AuthGuard: User lacks required roles:', requiredRoles);
            router.navigate(['/dashboard']);
            return false;
          }
          return true;
        } else {
          console.log('AuthGuard: User not authenticated, redirecting to login');
          router.navigate(['/auth/login'], {
            queryParams: { returnTo: state.url }
          });
          return false;
        }
      })
    );
  }

  // If already initialized, check authentication
  if (authService.isAuthenticated()) {
    // Check role-based access if specified in route data
    const requiredRoles = route.data?.['roles'] as string[];
    if (requiredRoles && !authService.hasRole(requiredRoles)) {
      console.log('AuthGuard: User lacks required roles:', requiredRoles);
      router.navigate(['/dashboard']);
      return false;
    }
    return true;
  } else {
    console.log('AuthGuard: User not authenticated, redirecting to login');
    router.navigate(['/auth/login'], {
      queryParams: { returnTo: state.url }
    });
    return false;
  }
};
