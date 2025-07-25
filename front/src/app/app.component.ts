import { Component, computed, inject, OnInit, signal } from '@angular/core';
import { RouterOutlet, Router, NavigationEnd } from '@angular/router';
import { MatToolbarModule } from '@angular/material/toolbar';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatMenuModule } from '@angular/material/menu';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { filter } from 'rxjs/operators';

import { AuthService } from './core/services/auth.service';
import { LoadingService } from './core/services/loading.service';
import { environment } from '../environments/environment';

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
      @if (shouldShowToolbar()) {
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

      <main class="main-content" [class.full-height]="!shouldShowToolbar()">
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

    .main-content.full-height {
      padding: 0;
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

  // Track current route as a signal
  private _currentRoute = signal('');
  readonly currentRoute = this._currentRoute.asReadonly();

  // Computed signal for admin access
  hasAdminAccess = computed(() => {
    const user = this.authService.currentUser();
    return user?.roles?.includes('admin') || user?.roles?.includes('moderator');
  });

  // Computed signal to determine if toolbar should be shown
  shouldShowToolbar = computed(() => {
    const isAuthenticated = this.authService.isAuthenticated();
    const route = this.currentRoute();
    const isLandingPage = route === '' || route === '/';
    const isAuthPage = route.startsWith('/auth/');

    return isAuthenticated && !isLandingPage && !isAuthPage;
  });

  ngOnInit(): void {
    // Track route changes
    this.router.events.pipe(
      filter(event => event instanceof NavigationEnd)
    ).subscribe((event: NavigationEnd) => {
      this._currentRoute.set(event.url.split('?')[0]); // Remove query params
    });

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
      console.log('🚪 Logout button clicked');

      // For logout, we want to let the backend handle the redirect to preserve query parameters
      // Instead of using the AuthService logout Observable, we'll redirect directly to the backend logout endpoint
      const logoutUrl = `${environment.apiUrl}/auth/logout`;
      console.log('🔗 Redirecting to backend logout:', logoutUrl);
      window.location.href = logoutUrl;

    } catch (error) {
      console.error('Logout error:', error);
      // Fallback navigation to homepage
      this.router.navigate(['/']);
    }
  }
}
