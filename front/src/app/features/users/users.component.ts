import { Component, inject, signal, computed } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatCardModule } from '@angular/material/card';
import { MatTableModule } from '@angular/material/table';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatPaginatorModule, PageEvent } from '@angular/material/paginator';
import { MatChipsModule } from '@angular/material/chips';
import { MatSnackBarModule, MatSnackBar } from '@angular/material/snack-bar';

import { UserService } from '../../core/services/user.service';
import { AuthService } from '../../core/services/auth.service';
import { User } from '../../core/models/user.model';

@Component({
  selector: 'app-users',
  standalone: true,
  imports: [
    CommonModule,
    MatCardModule,
    MatTableModule,
    MatButtonModule,
    MatIconModule,
    MatPaginatorModule,
    MatChipsModule,
    MatSnackBarModule
  ],
  template: `
    <div class="users-container">
      <div class="users-header">
        <h1>User Management</h1>
        <p>Manage system users and their permissions</p>
      </div>

      <mat-card class="users-card">
        <mat-card-header>
          <mat-card-title>Users</mat-card-title>
          <mat-card-subtitle>Total: {{ totalUsers() }}</mat-card-subtitle>
        </mat-card-header>

        <mat-card-content>
          @if (isLoading()) {
            <div class="loading-container">
              <p>Loading users...</p>
            </div>
          } @else {
            <table mat-table [dataSource]="users()" class="users-table">
              <!-- Name Column -->
              <ng-container matColumnDef="name">
                <th mat-header-cell *matHeaderCellDef>Name</th>
                <td mat-cell *matCellDef="let user">
                  <div class="user-info">
                    <strong>{{ user.nni }}</strong>
                    <br>
                    <strong>{{ user.fullName }}</strong>
                    <br>
                    <small>{{ user.email }}</small>
                  </div>
                </td>
              </ng-container>

              <!-- Role Column -->
              <ng-container matColumnDef="role">
                <th mat-header-cell *matHeaderCellDef>Role</th>
                <td mat-cell *matCellDef="let user">
                  <mat-chip [class]="'role-chip-' + user.role">
                    {{ user.role | titlecase }}
                  </mat-chip>
                </td>
              </ng-container>

              <!-- Status Column -->
              <ng-container matColumnDef="status">
                <th mat-header-cell *matHeaderCellDef>Status</th>
                <td mat-cell *matCellDef="let user">
                  <mat-chip [class]="user.isActive ? 'status-active' : 'status-inactive'">
                    {{ user.isActive ? 'Active' : 'Inactive' }}
                  </mat-chip>
                </td>
              </ng-container>

              <!-- Last Login Column -->
              <ng-container matColumnDef="lastLogin">
                <th mat-header-cell *matHeaderCellDef>Last Login</th>
                <td mat-cell *matCellDef="let user">
                  {{ user.lastLoginAt ? (user.lastLoginAt | date:'short') : 'Never' }}
                </td>
              </ng-container>

              <!-- Actions Column -->
              <ng-container matColumnDef="actions">
                <th mat-header-cell *matHeaderCellDef>Actions</th>
                <td mat-cell *matCellDef="let user">
                  @if (authService.isAdminUser()) {
                    <button mat-icon-button (click)="editUser(user)">
                      <mat-icon>edit</mat-icon>
                    </button>
                    <button mat-icon-button (click)="deleteUser(user)" color="warn">
                      <mat-icon>delete</mat-icon>
                    </button>
                  } @else {
                    <button mat-icon-button (click)="viewUser(user)">
                      <mat-icon>visibility</mat-icon>
                    </button>
                  }
                </td>
              </ng-container>

              <tr mat-header-row *matHeaderRowDef="displayedColumns"></tr>
              <tr mat-row *matRowDef="let row; columns: displayedColumns;"></tr>
            </table>

            <mat-paginator
              [length]="totalUsers()"
              [pageSize]="pageSize()"
              [pageSizeOptions]="[5, 10, 20, 50]"
              (page)="onPageChange($event)"
              showFirstLastButtons>
            </mat-paginator>
          }
        </mat-card-content>
      </mat-card>
    </div>
  `,
  styles: [`
    .users-container {
      padding: 24px;
      max-width: 1200px;
      margin: 0 auto;
    }

    .users-header {
      margin-bottom: 32px;
    }

    .users-header h1 {
      margin: 0 0 8px 0;
      color: rgba(0, 0, 0, 0.87);
    }

    .users-header p {
      margin: 0;
      color: rgba(0, 0, 0, 0.6);
    }

    .users-card {
      width: 100%;
    }

    .loading-container {
      text-align: center;
      padding: 24px;
    }

    .users-table {
      width: 100%;
      margin-bottom: 16px;
    }

    .user-info strong {
      font-weight: 500;
    }

    .user-info small {
      color: rgba(0, 0, 0, 0.6);
    }

    .role-chip-admin {
      background-color: #f44336;
      color: white;
    }

    .role-chip-moderator {
      background-color: #ff9800;
      color: white;
    }

    .role-chip-user {
      background-color: #4caf50;
      color: white;
    }

    .status-active {
      background-color: #4caf50;
      color: white;
    }

    .status-inactive {
      background-color: #f44336;
      color: white;
    }

    @media (max-width: 768px) {
      .users-table {
        font-size: 12px;
      }
    }
  `]
})
export class UsersComponent {
  private userService = inject(UserService);
  private snackBar = inject(MatSnackBar);

  authService = inject(AuthService);

  // Signals
  users = signal<User[]>([]);
  totalUsers = signal<number>(0);
  currentPage = signal<number>(1);
  pageSize = signal<number>(10);
  isLoading = signal<boolean>(false);

  // Computed
  displayedColumns = computed(() => {
    return ['name', 'role', 'status', 'lastLogin', 'actions'];
  });

  constructor() {
    this.loadUsers();
  }

  loadUsers(): void {
    this.isLoading.set(true);

    this.userService.getUsers({
      page: this.currentPage(),
      limit: this.pageSize()
    }).subscribe({
      next: (response) => {
        this.users.set(response.users || response.data || []);
        this.totalUsers.set(response.total);
      },
      error: (error) => {
        console.error('Failed to load users:', error);
        this.snackBar.open('Failed to load users', 'Close', {
          duration: 3000
        });
      },
      complete: () => {
        this.isLoading.set(false);
      }
    });
  }

  onPageChange(event: PageEvent): void {
    this.currentPage.set(event.pageIndex + 1);
    this.pageSize.set(event.pageSize);
    this.loadUsers();
  }

  editUser(user: User): void {
    // TODO: Implement edit user dialog
    console.log('Edit user:', user);
    this.snackBar.open('Edit user functionality coming soon', 'Close', {
      duration: 3000
    });
  }

  viewUser(user: User): void {
    // TODO: Implement view user dialog
    console.log('View user:', user);
    this.snackBar.open('View user functionality coming soon', 'Close', {
      duration: 3000
    });
  }

  deleteUser(user: User): void {
    // TODO: Implement delete confirmation dialog
    if (confirm(`Are you sure you want to delete user ${user.fullName}?`)) {
      this.userService.deleteUser(user.id).subscribe({
        next: () => {
          this.snackBar.open('User deleted successfully', 'Close', {
            duration: 3000
          });
          this.loadUsers();
        },
        error: (error) => {
          console.error('Failed to delete user:', error);
          this.snackBar.open('Failed to delete user', 'Close', {
            duration: 3000
          });
        }
      });
    }
  }
}
