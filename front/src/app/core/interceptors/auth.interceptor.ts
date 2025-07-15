import { inject } from '@angular/core';
import { HttpInterceptorFn, HttpErrorResponse } from '@angular/common/http';
import { Router } from '@angular/router';
import { catchError, finalize } from 'rxjs/operators';
import { throwError } from 'rxjs';

import { LoadingService } from '../services/loading.service';
import { environment } from '../../../environments/environment';

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const loadingService = inject(LoadingService);
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
        // Redirect to SSO login directly with returnTo parameter
        const currentUrl = router.url;
        const params = new URLSearchParams();
        if (currentUrl && !currentUrl.startsWith('/auth/')) {
          params.append('returnTo', currentUrl);
        }

        const loginUrl = `${environment.apiUrl}/auth/login${params.toString() ? '?' + params.toString() : ''}`;
        window.location.href = loginUrl;
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
