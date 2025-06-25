import { inject } from '@angular/core';
import { HttpInterceptorFn, HttpErrorResponse } from '@angular/common/http';
import { Router } from '@angular/router';
import { catchError, finalize } from 'rxjs/operators';
import { throwError } from 'rxjs';

import { LoadingService } from '../services/loading.service';
import { AuthService } from '../services/auth.service';

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const loadingService = inject(LoadingService);
  const authService = inject(AuthService);
  const router = inject(Router);

  // Start loading
  loadingService.start();

  // Add credentials to include cookies/session
  const modifiedReq = req.clone({
    setHeaders: {
      'Content-Type': 'application/json'
    },
    withCredentials: true
  });

  return next(modifiedReq).pipe(
    catchError((error: HttpErrorResponse) => {
      // Handle authentication errors
      if (error.status === 401) {
        // Clear auth state and redirect to login
        authService.refreshSession().subscribe({
          next: (session) => {
            if (!session?.isAuthenticated) {
              router.navigate(['/auth/login']);
            }
          },
          error: () => {
            router.navigate(['/auth/login']);
          }
        });
      }

      // Handle authorization errors
      if (error.status === 403) {
        router.navigate(['/dashboard']);
      }

      return throwError(() => error);
    }),
    finalize(() => {
      // Stop loading
      loadingService.stop();
    })
  );
};
