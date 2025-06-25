import { Component, inject, OnInit } from '@angular/core';

import { Router } from '@angular/router';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatCardModule } from '@angular/material/card';

import { AuthService } from '../../../core/services/auth.service';

@Component({
  selector: 'app-callback',
  standalone: true,
  imports: [
    MatProgressSpinnerModule,
    MatCardModule
],
  template: `
    <div class="callback-container">
      <mat-card class="callback-card">
        <mat-card-content>
          <div class="callback-content">
            <mat-spinner></mat-spinner>
            <h2>Processing Login...</h2>
            <p>Please wait while we complete your authentication.</p>
          </div>
        </mat-card-content>
      </mat-card>
    </div>
  `,
  styles: [`
    .callback-container {
      height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      padding: 16px;
    }

    .callback-card {
      width: 100%;
      max-width: 400px;
      padding: 24px;
    }

    .callback-content {
      text-align: center;
      padding: 24px 0;
    }

    .callback-content h2 {
      margin: 16px 0 8px 0;
      color: rgba(0, 0, 0, 0.87);
    }

    .callback-content p {
      margin: 0;
      color: rgba(0, 0, 0, 0.6);
    }
  `]
})
export class CallbackComponent implements OnInit {
  private authService = inject(AuthService);
  private router = inject(Router);

  ngOnInit(): void {
    // The backend will handle the OIDC callback and redirect
    // This component just shows a loading state
    setTimeout(() => {
      // Refresh session and redirect
      this.authService.refreshSession().subscribe({
        next: (session) => {
          if (session?.isAuthenticated) {
            this.router.navigate(['/dashboard']);
          } else {
            this.router.navigate(['/auth/login']);
          }
        },
        error: () => {
          this.router.navigate(['/auth/login']);
        }
      });
    }, 1000);
  }
}
