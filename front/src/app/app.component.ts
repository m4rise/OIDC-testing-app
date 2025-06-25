import { Component, computed, inject, OnInit } from '@angular/core';

import { RouterOutlet, Router } from '@angular/router';
import { MatToolbarModule } from '@angular/material/toolbar';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatMenuModule } from '@angular/material/menu';
import { MatProgressBarModule } from '@angular/material/progress-bar';

import { AuthService } from './core/services/auth.service';
import { LoadingService } from './core/services/loading.service';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [
    RouterOutlet,
    MatToolbarModule,
    MatButtonModule,
    MatIconModule,
    MatMenuModule,
    MatProgressBarModule
],
  template: `
    <div class="app-container">
      @if (authService.isAuthenticated()) {
        <mat-toolbar color="primary">
          <span>My App</span>

          <div class="spacer"></div>

          <button mat-button routerLink="/dashboard">
            <mat-icon>dashboard</mat-icon>
            Dashboard
          </button>

          <button mat-button routerLink="/profile">
            <mat-icon>person</mat-icon>
            Profile
          </button>

          @if (hasAdminAccess()) {
            <button mat-button routerLink="/users">
              <mat-icon>people</mat-icon>
              Users
            </button>
          }

          @if (hasAdminAccess()) {
            <button mat-button routerLink="/admin">
              <mat-icon>admin_panel_settings</mat-icon>
              Admin
            </button>
          }

          <button mat-icon-button [matMenuTriggerFor]="userMenu">
            <mat-icon>account_circle</mat-icon>
          </button>

          <mat-menu #userMenu="matMenu">
            <button mat-menu-item routerLink="/profile">
              <mat-icon>person</mat-icon>
              <span>Profile</span>
            </button>
            <button mat-menu-item (click)="logout()">
              <mat-icon>logout</mat-icon>
              <span>Logout</span>
            </button>
          </mat-menu>
        </mat-toolbar>

        @if (loadingService.isLoading()) {
          <mat-progress-bar mode="indeterminate"></mat-progress-bar>
        }
      }

      <main class="main-content">
        <router-outlet></router-outlet>
      </main>
    </div>
  `,
  styles: [`
    .app-container {
      height: 100vh;
      display: flex;
      flex-direction: column;
    }

    .spacer {
      flex: 1 1 auto;
    }

    .main-content {
      flex: 1;
      overflow-y: auto;
      padding: 16px;
    }

    mat-toolbar {
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }

    mat-toolbar button {
      margin-right: 8px;
    }

    mat-toolbar button mat-icon {
      margin-right: 4px;
    }
  `]
})
export class AppComponent implements OnInit {
  private router = inject(Router);

  authService = inject(AuthService);
  loadingService = inject(LoadingService);

  // Computed signal for admin access
  hasAdminAccess = computed(() => {
    const user = this.authService.currentUser();
    return user?.role === 'admin' || user?.role === 'moderator';
  });

  ngOnInit(): void {
    // Initialize auth service after component initialization
    console.log('AppComponent: Initializing auth service...');
    this.authService.initialize().then(() => {
      console.log('AppComponent: Auth service initialization complete');
    }).catch(error => {
      console.error('AppComponent: Auth service initialization failed:', error);
    });
  }

  async logout(): Promise<void> {
    try {
      await this.authService.logout();
      this.router.navigate(['/auth/login']);
    } catch (error) {
      console.error('Logout error:', error);
    }
  }
}
