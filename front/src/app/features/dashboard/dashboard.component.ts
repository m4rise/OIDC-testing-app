import { Component, inject, computed } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatCardModule } from '@angular/material/card';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatGridListModule } from '@angular/material/grid-list';
import { RouterModule } from '@angular/router';

import { AuthService } from '../../core/services/auth.service';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [
    CommonModule,
    MatCardModule,
    MatButtonModule,
    MatIconModule,
    MatGridListModule,
    RouterModule
  ],
  template: `
    <div class="dashboard-container">
      <div class="dashboard-header">
        <h1>Dashboard</h1>
        <p>Welcome back, {{ userDisplayName() }}!</p>
      </div>

      <mat-grid-list cols="3" rowHeight="200px" gutterSize="16px" class="dashboard-grid">
        <!-- Profile Card -->
        <mat-grid-tile>
          <mat-card class="dashboard-card">
            <mat-card-header>
              <mat-icon mat-card-avatar>person</mat-icon>
              <mat-card-title>Profile</mat-card-title>
              <mat-card-subtitle>Manage your account</mat-card-subtitle>
            </mat-card-header>
            <mat-card-actions>
              <button mat-button routerLink="/profile">
                VIEW PROFILE
              </button>
            </mat-card-actions>
          </mat-card>
        </mat-grid-tile>

        <!-- Users Management (Admin/Moderator only) -->
        @if (authService.isModerator()) {
          <mat-grid-tile>
            <mat-card class="dashboard-card">
              <mat-card-header>
                <mat-icon mat-card-avatar>people</mat-icon>
                <mat-card-title>Users</mat-card-title>
                <mat-card-subtitle>Manage system users</mat-card-subtitle>
              </mat-card-header>
              <mat-card-actions>
                <button mat-button routerLink="/users">
                  MANAGE USERS
                </button>
              </mat-card-actions>
            </mat-card>
          </mat-grid-tile>
        }

        <!-- Admin Panel (Admin only) -->
        @if (authService.isAdmin()) {
          <mat-grid-tile>
            <mat-card class="dashboard-card">
              <mat-card-header>
                <mat-icon mat-card-avatar>admin_panel_settings</mat-icon>
                <mat-card-title>Administration</mat-card-title>
                <mat-card-subtitle>System administration</mat-card-subtitle>
              </mat-card-header>
              <mat-card-actions>
                <button mat-button routerLink="/admin">
                  ADMIN PANEL
                </button>
              </mat-card-actions>
            </mat-card>
          </mat-grid-tile>
        }

        <!-- Settings Card -->
        <mat-grid-tile>
          <mat-card class="dashboard-card">
            <mat-card-header>
              <mat-icon mat-card-avatar>settings</mat-icon>
              <mat-card-title>Settings</mat-card-title>
              <mat-card-subtitle>App preferences</mat-card-subtitle>
            </mat-card-header>
            <mat-card-actions>
              <button mat-button disabled>
                COMING SOON
              </button>
            </mat-card-actions>
          </mat-card>
        </mat-grid-tile>
      </mat-grid-list>

      <!-- User Info Section -->
      <div class="user-info-section">
        <mat-card class="user-info-card">
          <mat-card-header>
            <mat-card-title>Your Account Information</mat-card-title>
          </mat-card-header>
          <mat-card-content>
            <div class="user-details">
              <div class="detail-item">
                <strong>NNI:</strong> {{ currentUser()?.nni }}
              </div>
              <div class="detail-item">
                <strong>Email:</strong> {{ currentUser()?.email }}
              </div>
              <div class="detail-item">
                <strong>Role:</strong>
                <span class="role-badge role-{{ currentUser()?.role }}">
                  {{ currentUser()?.role | titlecase }}
                </span>
              </div>
              <div class="detail-item">
                <strong>Permissions:</strong>
                <div class="permissions-list">
                  @for (permission of currentUser()?.permissions; track permission) {
                    <span class="permission-chip">{{ permission }}</span>
                  }
                </div>
              </div>
              @if (currentUser()?.lastLoginAt) {
                <div class="detail-item">
                  <strong>Last Login:</strong> {{ currentUser()?.lastLoginAt | date:'medium' }}
                </div>
              }
            </div>
          </mat-card-content>
        </mat-card>
      </div>
    </div>
  `,
  styles: [`
    .dashboard-container {
      padding: 24px;
      max-width: 1200px;
      margin: 0 auto;
    }

    .dashboard-header {
      margin-bottom: 32px;
    }

    .dashboard-header h1 {
      margin: 0 0 8px 0;
      color: rgba(0, 0, 0, 0.87);
    }

    .dashboard-header p {
      margin: 0;
      color: rgba(0, 0, 0, 0.6);
      font-size: 16px;
    }

    .dashboard-grid {
      margin-bottom: 32px;
    }

    .dashboard-card {
      width: 100%;
      height: 100%;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }

    .user-info-section {
      margin-top: 32px;
    }

    .user-info-card {
      width: 100%;
    }

    .user-details {
      display: flex;
      flex-direction: column;
      gap: 16px;
    }

    .detail-item {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .role-badge {
      padding: 4px 12px;
      border-radius: 16px;
      font-size: 12px;
      font-weight: 500;
      text-transform: uppercase;
    }

    .role-admin {
      background-color: #f44336;
      color: white;
    }

    .role-moderator {
      background-color: #ff9800;
      color: white;
    }

    .role-user {
      background-color: #4caf50;
      color: white;
    }

    .permissions-list {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }

    .permission-chip {
      background-color: #e0e0e0;
      padding: 4px 8px;
      border-radius: 12px;
      font-size: 12px;
    }

    @media (max-width: 768px) {
      .dashboard-grid {
        grid-template-columns: 1fr !important;
      }
    }
  `]
})
export class DashboardComponent {
  authService = inject(AuthService);

  // Computed signals
  currentUser = this.authService.currentUser;
  userDisplayName = computed(() => {
    const user = this.currentUser();
    return user?.fullName || user?.email || 'User';
  });
}
