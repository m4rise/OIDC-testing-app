import { inject } from '@angular/core';
import { Router, type CanActivateFn } from '@angular/router';
import { map, take } from 'rxjs/operators';

import { AuthService } from '../services/auth.service';

export const authGuard: CanActivateFn = (route, state) => {
  const authService = inject(AuthService);
  const router = inject(Router);

  // Wait for initialization to complete
  if (!authService.isInitialized()) {
    return authService.refreshSession().pipe(
      take(1),
      map(() => {
        if (authService.isAuthenticated()) {
          // Check role-based access if specified in route data
          const requiredRoles = route.data?.['roles'] as string[];
          if (requiredRoles && !authService.hasRole(requiredRoles)) {
            router.navigate(['/dashboard']);
            return false;
          }
          return true;
        } else {
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
      router.navigate(['/dashboard']);
      return false;
    }
    return true;
  } else {
    router.navigate(['/auth/login'], {
      queryParams: { returnTo: state.url }
    });
    return false;
  }
};
