import { Component, inject, OnInit } from '@angular/core';
import { Router, ActivatedRoute } from '@angular/router';
import { MatCardModule } from '@angular/material/card';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { CommonModule } from '@angular/common';

import { AuthService } from '../../core/services/auth.service';

@Component({
  selector: 'app-landing',
  standalone: true,
  imports: [
    CommonModule,
    MatCardModule,
    MatButtonModule,
    MatIconModule,
    MatProgressSpinnerModule
  ],
  template: `
    <div class="landing-container">
      <div class="landing-content">
        <mat-card class="welcome-card">
          <mat-card-header>
            <div mat-card-avatar class="app-avatar">
              <mat-icon>home</mat-icon>
            </div>
            <mat-card-title>Welcome to My App</mat-card-title>
            <mat-card-subtitle>
              @if (showLoggedOutMessage) {
                You have been successfully logged out
              } @else if (showErrorMessage) {
                Authentication failed - please try again
              } @else {
                Please sign in to continue
              }
            </mat-card-subtitle>
          </mat-card-header>

          <mat-card-content>
            @if (isCheckingAuth) {
              <div class="checking-auth">
                <mat-spinner diameter="40"></mat-spinner>
                <p>Checking authentication status...</p>
              </div>
            } @else {
              <div class="auth-actions">
                @if (showLoggedOutMessage) {
                  <p class="success-message">
                    <mat-icon color="primary">check_circle</mat-icon>
                    You have been successfully logged out.
                  </p>
                } @else if (showErrorMessage) {
                  <p class="error-message">
                    <mat-icon color="warn">error</mat-icon>
                    There was an issue with authentication. Please try signing in again.
                  </p>
                }

                <p class="info-text">
                  To access the application, you'll need to sign in with your credentials.
                </p>

                <button
                  mat-raised-button
                  color="primary"
                  (click)="signIn()"
                  class="sign-in-button">
                  <mat-icon>login</mat-icon>
                  Sign In
                </button>
              </div>
            }
          </mat-card-content>
        </mat-card>

        <div class="app-info">
          <h3>About This Application</h3>
          <ul>
            <li>Secure authentication with SSO</li>
            <li>Modern Angular 20+ architecture</li>
            <li>Role-based access control</li>
            <li>Real-time session management</li>
          </ul>
        </div>
      </div>
    </div>
  `,
  styles: [`
    .landing-container {
      min-height: 100vh;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 16px;
    }

    .landing-content {
      max-width: 600px;
      width: 100%;
    }

    .welcome-card {
      margin-bottom: 24px;
      padding: 24px;
    }

    .app-avatar {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      display: flex;
      align-items: center;
      justify-content: center;
    }

    .checking-auth {
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 24px 0;
      gap: 16px;
    }

    .auth-actions {
      text-align: center;
      padding: 16px 0;
    }

    .success-message, .error-message {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      margin-bottom: 16px;
      padding: 12px;
      border-radius: 4px;
    }

    .success-message {
      background-color: #e8f5e8;
      color: #2e7d32;
      border: 1px solid #c8e6c9;
    }

    .error-message {
      background-color: #ffebee;
      color: #c62828;
      border: 1px solid #ffcdd2;
    }

    .info-text {
      margin: 16px 0;
      color: rgba(0, 0, 0, 0.7);
    }

    .sign-in-button {
      margin-top: 16px;
      padding: 12px 32px;
      font-size: 16px;
    }

    .sign-in-button mat-icon {
      margin-right: 8px;
    }

    .app-info {
      background: rgba(255, 255, 255, 0.95);
      border-radius: 8px;
      padding: 24px;
      text-align: center;
    }

    .app-info h3 {
      margin-top: 0;
      color: #333;
    }

    .app-info ul {
      list-style: none;
      padding: 0;
      margin: 16px 0 0 0;
    }

    .app-info li {
      padding: 8px 0;
      color: #666;
    }

    .app-info li::before {
      content: '✓';
      color: #4caf50;
      font-weight: bold;
      margin-right: 8px;
    }

    @media (max-width: 600px) {
      .landing-container {
        padding: 8px;
      }

      .welcome-card {
        padding: 16px;
      }
    }
  `]
})
export class LandingComponent implements OnInit {
  private authService = inject(AuthService);
  private router = inject(Router);
  private route = inject(ActivatedRoute);

  isCheckingAuth = false;
  showLoggedOutMessage = false;
  showErrorMessage = false;

  ngOnInit(): void {
    // Check query parameters for logout/error states
    const queryParams = this.route.snapshot.queryParams;
    console.log('LandingComponent: Query parameters received:', queryParams);

    this.showLoggedOutMessage = queryParams['logged_out'] === 'true';
    this.showErrorMessage = !!queryParams['error'];

    console.log('LandingComponent: showLoggedOutMessage =', this.showLoggedOutMessage);
    console.log('LandingComponent: showErrorMessage =', this.showErrorMessage);

    // If no logout/error state, redirect unauthenticated users directly to SSO
    if (!this.showLoggedOutMessage && !this.showErrorMessage) {
      console.log('LandingComponent: No logout/error state, checking if should redirect to SSO');
      this.checkAndRedirectIfUnauthenticated();
    } else {
      // Only check auth status if we have logout/error state (show landing page)
      this.checkAuthenticationStatus();
    }
  }

  private async checkAuthenticationStatus(): Promise<void> {
    this.isCheckingAuth = true;

    try {
      // Ensure auth service is initialized
      if (!this.authService.isInitialized()) {
        await this.authService.initialize();
      }

      // If user is authenticated, redirect to dashboard
      if (this.authService.isAuthenticated()) {
        console.log('LandingComponent: User is authenticated, redirecting to dashboard');
        this.router.navigate(['/dashboard']);
        return;
      }

      // If user is not authenticated but no logout/error state, redirect to SSO
      if (!this.showLoggedOutMessage && !this.showErrorMessage) {
        console.log('LandingComponent: User is not authenticated and no logout/error state, redirecting to SSO');
        this.authService.login();
        return;
      }

      console.log('LandingComponent: User is not authenticated, showing landing page for logout/error state');
    } catch (error) {
      console.error('LandingComponent: Error checking authentication:', error);
      this.showErrorMessage = true;
    } finally {
      this.isCheckingAuth = false;
    }
  }

  private async checkAndRedirectIfUnauthenticated(): Promise<void> {
    this.isCheckingAuth = true;

    try {
      // Ensure auth service is initialized
      if (!this.authService.isInitialized()) {
        await this.authService.initialize();
      }

      // If user is authenticated, redirect to dashboard
      if (this.authService.isAuthenticated()) {
        console.log('LandingComponent: User is authenticated, redirecting to dashboard');
        this.router.navigate(['/dashboard']);
        return;
      }

      // User is not authenticated and no logout/error state, redirect to SSO
      console.log('LandingComponent: User is not authenticated, redirecting directly to SSO');
      this.authService.login();
    } catch (error) {
      console.error('LandingComponent: Error checking authentication:', error);
      // On error, show error message on landing page
      this.showErrorMessage = true;
      this.isCheckingAuth = false;
    }
  }

  signIn(): void {
    console.log('LandingComponent: Sign in button clicked');
    // Trigger SSO authentication
    this.authService.login();
  }
}
