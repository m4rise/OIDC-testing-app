import { Component, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ReactiveFormsModule, FormBuilder, FormGroup, Validators } from '@angular/forms';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatSnackBarModule, MatSnackBar } from '@angular/material/snack-bar';

import { AuthService } from '../../core/services/auth.service';
import { UserService } from '../../core/services/user.service';

@Component({
  selector: 'app-profile',
  standalone: true,
  imports: [
    CommonModule,
    ReactiveFormsModule,
    MatCardModule,
    MatFormFieldModule,
    MatInputModule,
    MatButtonModule,
    MatIconModule,
    MatSnackBarModule
  ],
  template: `
    <div class="profile-container">
      <div class="profile-header">
        <h1>Profile</h1>
        <p>Manage your personal information</p>
      </div>

      <div class="profile-content">
        <mat-card class="profile-card">
          <mat-card-header>
            <mat-icon mat-card-avatar>person</mat-icon>
            <mat-card-title>Personal Information</mat-card-title>
            <mat-card-subtitle>Update your profile details</mat-card-subtitle>
          </mat-card-header>

          <mat-card-content>
            <form [formGroup]="profileForm" (ngSubmit)="updateProfile()">

              <div class="form-row">
                <mat-form-field appearance="outline" class="full-width">
                  <mat-label>NNI</mat-label>
                  <input matInput [value]="authService.currentUser()?.nni | titlecase" readonly>
                  <mat-icon matSuffix>security</mat-icon>
                </mat-form-field>
              </div>

              <div class="form-row">
                <mat-form-field appearance="outline" class="full-width">
                  <mat-label>Email</mat-label>
                  <input matInput formControlName="email" readonly>
                  <mat-icon matSuffix>email</mat-icon>
                </mat-form-field>
              </div>

              <div class="form-row">
                <mat-form-field appearance="outline" class="half-width">
                  <mat-label>First Name</mat-label>
                  <input matInput formControlName="firstName">
                  <mat-icon matSuffix>person</mat-icon>
                </mat-form-field>

                <mat-form-field appearance="outline" class="half-width">
                  <mat-label>Last Name</mat-label>
                  <input matInput formControlName="lastName">
                  <mat-icon matSuffix>person_outline</mat-icon>
                </mat-form-field>
              </div>

              <div class="form-row">
                <mat-form-field appearance="outline" class="full-width">
                  <mat-label>Roles</mat-label>
                  <input matInput [value]="authService.currentUser()?.roles?.join(', ') | titlecase" readonly>
                  <mat-icon matSuffix>security</mat-icon>
                </mat-form-field>
              </div>

              <div class="form-actions">
                <button
                  mat-raised-button
                  color="primary"
                  type="submit"
                  [disabled]="profileForm.invalid || isLoading()">
                  @if (isLoading()) {
                    <ng-container>
                      <mat-icon>hourglass_empty</mat-icon>
                      Updating...
                    </ng-container>
                  } @else {
                    <ng-container>
                      <mat-icon>save</mat-icon>
                      Save Changes
                    </ng-container>
                  }
                </button>

                <button
                  mat-button
                  type="button"
                  (click)="resetForm()"
                  [disabled]="isLoading()">
                  <mat-icon>refresh</mat-icon>
                  Reset
                </button>
              </div>
            </form>
          </mat-card-content>
        </mat-card>

        <!-- Account Information Card -->
        <mat-card class="info-card">
          <mat-card-header>
            <mat-icon mat-card-avatar>info</mat-icon>
            <mat-card-title>Account Information</mat-card-title>
          </mat-card-header>

          <mat-card-content>
            <div class="info-grid">
              <div class="info-item">
                <strong>Account Status:</strong>
                <span class="status-badge"
                      [class.active]="authService.currentUser()?.isActive"
                      [class.inactive]="!authService.currentUser()?.isActive">
                  {{ authService.currentUser()?.isActive ? 'Active' : 'Inactive' }}
                </span>
              </div>

              <div class="info-item">
                <strong>Permissions:</strong>
                <div class="permissions-list">
                  @for (permission of authService.currentUser()?.permissions; track permission) {
                    <span class="permission-chip">{{ permission }}</span>
                  }
                </div>
              </div>

              @if (authService.currentUser()?.createdAt) {
                <div class="info-item">
                  <strong>Member Since:</strong>
                  <span>{{ authService.currentUser()?.createdAt | date:'mediumDate' }}</span>
                </div>
              }

              @if (authService.currentUser()?.lastLoginAt) {
                <div class="info-item">
                  <strong>Last Login:</strong>
                  <span>{{ authService.currentUser()?.lastLoginAt | date:'medium' }}</span>
                </div>
              }
            </div>
          </mat-card-content>
        </mat-card>
      </div>
    </div>
  `,
  styles: [`
    .profile-container {
      padding: 24px;
      max-width: 800px;
      margin: 0 auto;
    }

    .profile-header {
      margin-bottom: 32px;
    }

    .profile-header h1 {
      margin: 0 0 8px 0;
      color: rgba(0, 0, 0, 0.87);
    }

    .profile-header p {
      margin: 0;
      color: rgba(0, 0, 0, 0.6);
    }

    .profile-content {
      display: flex;
      flex-direction: column;
      gap: 24px;
    }

    .profile-card {
      width: 100%;
    }

    .form-row {
      display: flex;
      gap: 16px;
      margin-bottom: 16px;
    }

    .full-width {
      width: 100%;
    }

    .half-width {
      width: calc(50% - 8px);
    }

    .form-actions {
      display: flex;
      gap: 16px;
      margin-top: 24px;
    }

    .info-card {
      width: 100%;
    }

    .info-grid {
      display: flex;
      flex-direction: column;
      gap: 16px;
    }

    .info-item {
      display: flex;
      flex-direction: column;
      gap: 8px;
    }

    .status-badge {
      padding: 4px 12px;
      border-radius: 16px;
      font-size: 12px;
      font-weight: 500;
      text-transform: uppercase;
      width: fit-content;
    }

    .status-badge.active {
      background-color: #4caf50;
      color: white;
    }

    .status-badge.inactive {
      background-color: #f44336;
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
      .form-row {
        flex-direction: column;
      }

      .half-width {
        width: 100%;
      }

      .form-actions {
        flex-direction: column;
      }
    }
  `]
})
export class ProfileComponent {
  private fb = inject(FormBuilder);
  private snackBar = inject(MatSnackBar);
  private userService = inject(UserService);

  authService = inject(AuthService);
  isLoading = signal(false);

  profileForm: FormGroup;

  constructor() {
    this.profileForm = this.fb.group({
      email: [{ value: '', disabled: true }],
      firstName: ['', [Validators.required, Validators.minLength(2)]],
      lastName: ['', [Validators.required, Validators.minLength(2)]]
    });

    // Initialize form with user data
    this.initializeForm();
  }

  private initializeForm(): void {
    const user = this.authService.currentUser();
    if (user) {
      this.profileForm.patchValue({
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName
      });
    }
  }

  updateProfile(): void {
    if (this.profileForm.valid) {
      this.isLoading.set(true);

      const formValue = this.profileForm.value;
      const user = this.authService.currentUser();

      if (user) {
        this.userService.updateProfile(user.id, {
          firstName: formValue.firstName,
          lastName: formValue.lastName
        }).subscribe({
          next: () => {
            this.snackBar.open('Profile updated successfully', 'Close', {
              duration: 3000,
              horizontalPosition: 'end',
              verticalPosition: 'top'
            });

            // Refresh session to get updated user data
            this.authService.refreshSession().subscribe();
          },
          error: (error) => {
            console.error('Profile update error:', error);
            this.snackBar.open('Failed to update profile', 'Close', {
              duration: 3000,
              horizontalPosition: 'end',
              verticalPosition: 'top'
            });
          },
          complete: () => {
            this.isLoading.set(false);
          }
        });
      }
    }
  }

  resetForm(): void {
    this.initializeForm();
  }
}
