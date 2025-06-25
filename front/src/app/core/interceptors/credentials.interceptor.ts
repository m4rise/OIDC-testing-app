import { Injectable } from '@angular/core';
import { HttpInterceptor, HttpRequest, HttpHandler, HttpEvent } from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable()
export class CredentialsInterceptor implements HttpInterceptor {
  intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    // Clone the request and add withCredentials: true to send cookies
    const credentialsReq = req.clone({
      // This ensures cookies are sent with cross-origin requests
      withCredentials: true
    });

    return next.handle(credentialsReq);
  }
}
