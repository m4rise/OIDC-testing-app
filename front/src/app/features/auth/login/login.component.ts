import { Component, inject } from '@angular/core';

import { MatCardModule } from '@angular/material/card';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';

import { AuthService } from '../../../core/services/auth.service';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [
    MatCardModule,
    MatButtonModule,
    MatIconModule,
    MatProgressSpinnerModule
],
  template: `
    <div class="login-container">
      <mat-card class="login-card">
        <mat-card-header>
          <mat-card-title>Welcome</mat-card-title>
          <mat-card-subtitle>Please sign in to continue</mat-card-subtitle>
        </mat-card-header>

        <mat-card-content>
          <div class="login-content">
            @if (authService.isLoading()) {
              <div class="loading-container">
                <mat-spinner></mat-spinner>
                <p>Redirecting to login...</p>
              </div>
            } @else {
              <div class="login-actions">
                <button
                  mat-raised-button
                  color="primary"
                  class="login-button"
                  (click)="login()">
                  <mat-icon>login</mat-icon>
                  Sign in with SSO
                </button>

                <p class="login-help">
                  You will be redirected to your organization's login page.
                </p>
              </div>
            }
          </div>
        </mat-card-content>
      </mat-card>
    </div>
  `,
  styles: [`
    .login-container {
      height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      padding: 16px;
    }

    .login-card {
      width: 100%;
      max-width: 400px;
      padding: 24px;
    }

    .login-content {
      text-align: center;
      padding: 24px 0;
    }

    .login-button {
      width: 100%;
      height: 48px;
      font-size: 16px;
      margin-bottom: 16px;
    }

    .login-button mat-icon {
      margin-right: 8px;
    }

    .login-help {
      color: rgba(0, 0, 0, 0.6);
      font-size: 14px;
      margin: 0;
    }

    .loading-container {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 16px;
    }

    .loading-container p {
      margin: 0;
      color: rgba(0, 0, 0, 0.6);
    }
  `]
})
export class LoginComponent {
  authService = inject(AuthService);

  login(): void {
    // Get return URL from query params if available
    const urlParams = new URLSearchParams(window.location.search);
    const returnTo = urlParams.get('returnTo') || '/dashboard';

    this.authService.login(returnTo);
  }
}
