import { Component, inject, signal } from '@angular/core';

import { MatCardModule } from '@angular/material/card';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatGridListModule } from '@angular/material/grid-list';

import { AuthService } from '../../core/services/auth.service';
import { UserService } from '../../core/services/user.service';

@Component({
  selector: 'app-admin',
  standalone: true,
  imports: [
    MatCardModule,
    MatButtonModule,
    MatIconModule,
    MatGridListModule
],
  template: `
    <div class="admin-container">
      <div class="admin-header">
        <h1>Administration</h1>
        <p>System administration and management tools</p>
      </div>

      <!-- Statistics Cards -->
      <div class="stats-section">
        <h2>System Statistics</h2>

        <mat-grid-list cols="4" rowHeight="150px" gutterSize="16px" class="stats-grid">
          <mat-grid-tile>
            <mat-card class="stat-card">
              <mat-card-content>
                <div class="stat-content">
                  <mat-icon class="stat-icon">people</mat-icon>
                  <div class="stat-info">
                    <h3>{{ userStats()?.total || 0 }}</h3>
                    <p>Total Users</p>
                  </div>
                </div>
              </mat-card-content>
            </mat-card>
          </mat-grid-tile>

          <mat-grid-tile>
            <mat-card class="stat-card">
              <mat-card-content>
                <div class="stat-content">
                  <mat-icon class="stat-icon">check_circle</mat-icon>
                  <div class="stat-info">
                    <h3>{{ userStats()?.active || 0 }}</h3>
                    <p>Active Users</p>
                  </div>
                </div>
              </mat-card-content>
            </mat-card>
          </mat-grid-tile>

          <mat-grid-tile>
            <mat-card class="stat-card">
              <mat-card-content>
                <div class="stat-content">
                  <mat-icon class="stat-icon">admin_panel_settings</mat-icon>
                  <div class="stat-info">
                    <h3>{{ userStats()?.byRole?.admin || 0 }}</h3>
                    <p>Administrators</p>
                  </div>
                </div>
              </mat-card-content>
            </mat-card>
          </mat-grid-tile>

          <mat-grid-tile>
            <mat-card class="stat-card">
              <mat-card-content>
                <div class="stat-content">
                  <mat-icon class="stat-icon">security</mat-icon>
                  <div class="stat-info">
                    <h3>{{ userStats()?.byRole?.moderator || 0 }}</h3>
                    <p>Moderators</p>
                  </div>
                </div>
              </mat-card-content>
            </mat-card>
          </mat-grid-tile>
        </mat-grid-list>
      </div>

      <!-- Admin Actions -->
      <div class="actions-section">
        <h2>Quick Actions</h2>

        <mat-grid-list cols="3" rowHeight="200px" gutterSize="16px" class="actions-grid">
          <mat-grid-tile>
            <mat-card class="action-card">
              <mat-card-header>
                <mat-icon mat-card-avatar>group_add</mat-icon>
                <mat-card-title>User Management</mat-card-title>
                <mat-card-subtitle>Create and manage users</mat-card-subtitle>
              </mat-card-header>
              <mat-card-actions>
                <button mat-button routerLink="/users">
                  MANAGE USERS
                </button>
              </mat-card-actions>
            </mat-card>
          </mat-grid-tile>

          <mat-grid-tile>
            <mat-card class="action-card">
              <mat-card-header>
                <mat-icon mat-card-avatar>settings</mat-icon>
                <mat-card-title>System Settings</mat-card-title>
                <mat-card-subtitle>Configure system settings</mat-card-subtitle>
              </mat-card-header>
              <mat-card-actions>
                <button mat-button disabled>
                  COMING SOON
                </button>
              </mat-card-actions>
            </mat-card>
          </mat-grid-tile>

          <mat-grid-tile>
            <mat-card class="action-card">
              <mat-card-header>
                <mat-icon mat-card-avatar>assessment</mat-icon>
                <mat-card-title>Reports</mat-card-title>
                <mat-card-subtitle>View system reports</mat-card-subtitle>
              </mat-card-header>
              <mat-card-actions>
                <button mat-button disabled>
                  COMING SOON
                </button>
              </mat-card-actions>
            </mat-card>
          </mat-grid-tile>
        </mat-grid-list>
      </div>
    </div>
  `,
  styles: [`
    .admin-container {
      padding: 24px;
      max-width: 1200px;
      margin: 0 auto;
    }

    .admin-header {
      margin-bottom: 32px;
    }

    .admin-header h1 {
      margin: 0 0 8px 0;
      color: rgba(0, 0, 0, 0.87);
    }

    .admin-header p {
      margin: 0;
      color: rgba(0, 0, 0, 0.6);
    }

    .stats-section,
    .actions-section {
      margin-bottom: 32px;
    }

    .stats-section h2,
    .actions-section h2 {
      margin: 0 0 16px 0;
      color: rgba(0, 0, 0, 0.87);
    }

    .stats-grid,
    .actions-grid {
      margin-bottom: 16px;
    }

    .stat-card,
    .action-card {
      width: 100%;
      height: 100%;
    }

    .stat-content {
      display: flex;
      align-items: center;
      gap: 16px;
      padding: 16px;
    }

    .stat-icon {
      font-size: 48px;
      height: 48px;
      width: 48px;
      color: #3f51b5;
    }

    .stat-info h3 {
      margin: 0 0 4px 0;
      font-size: 24px;
      font-weight: 500;
      color: rgba(0, 0, 0, 0.87);
    }

    .stat-info p {
      margin: 0;
      color: rgba(0, 0, 0, 0.6);
      font-size: 14px;
    }

    .action-card {
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }

    @media (max-width: 768px) {
      .stats-grid {
        grid-template-columns: 1fr 1fr !important;
      }

      .actions-grid {
        grid-template-columns: 1fr !important;
      }
    }

    @media (max-width: 480px) {
      .stats-grid {
        grid-template-columns: 1fr !important;
      }
    }
  `]
})
export class AdminComponent {
  authService = inject(AuthService);
  private userService = inject(UserService);

  userStats = signal<any>(null);

  constructor() {
    this.loadUserStats();
  }

  private loadUserStats(): void {
    this.userService.getUserStats().subscribe({
      next: (stats) => {
        this.userStats.set(stats);
      },
      error: (error) => {
        console.error('Failed to load user stats:', error);
      }
    });
  }
}
