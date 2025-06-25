import { Component } from '@angular/core';

import { MatCardModule } from '@angular/material/card';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { RouterModule } from '@angular/router';

@Component({
  selector: 'app-not-found',
  standalone: true,
  imports: [
    MatCardModule,
    MatButtonModule,
    MatIconModule,
    RouterModule
],
  template: `
    <div class="not-found-container">
      <mat-card class="not-found-card">
        <mat-card-content>
          <div class="not-found-content">
            <mat-icon class="not-found-icon">error_outline</mat-icon>
            <h1>404 - Page Not Found</h1>
            <p>The page you're looking for doesn't exist.</p>
            <button mat-raised-button color="primary" routerLink="/dashboard">
              <mat-icon>home</mat-icon>
              Go to Dashboard
            </button>
          </div>
        </mat-card-content>
      </mat-card>
    </div>
  `,
  styles: [`
    .not-found-container {
      height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 16px;
    }

    .not-found-card {
      width: 100%;
      max-width: 400px;
      text-align: center;
    }

    .not-found-content {
      padding: 24px;
    }

    .not-found-icon {
      font-size: 64px;
      height: 64px;
      width: 64px;
      color: rgba(0, 0, 0, 0.54);
      margin-bottom: 16px;
    }

    h1 {
      margin: 16px 0;
      color: rgba(0, 0, 0, 0.87);
    }

    p {
      margin-bottom: 24px;
      color: rgba(0, 0, 0, 0.6);
    }

    button mat-icon {
      margin-right: 8px;
    }
  `]
})
export class NotFoundComponent {}
