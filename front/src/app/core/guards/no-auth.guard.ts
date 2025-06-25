import { inject } from '@angular/core';
import { Router, type CanActivateFn } from '@angular/router';
import { map, take } from 'rxjs/operators';

import { AuthService } from '../services/auth.service';

export const noAuthGuard: CanActivateFn = (route, state) => {
  const authService = inject(AuthService);
  const router = inject(Router);

  // Wait for initialization to complete
  if (!authService.isInitialized()) {
    return authService.refreshSession().pipe(
      take(1),
      map(() => {
        if (authService.isAuthenticated()) {
          router.navigate(['/dashboard']);
          return false;
        } else {
          return true;
        }
      })
    );
  }

  // If already initialized, check authentication
  if (authService.isAuthenticated()) {
    router.navigate(['/dashboard']);
    return false;
  } else {
    return true;
  }
};
