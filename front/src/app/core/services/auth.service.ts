import { Injectable, signal, computed, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Router } from '@angular/router';
import { Observable, BehaviorSubject, throwError, of } from 'rxjs';
import { catchError, tap, map } from 'rxjs/operators';

import { User, SessionInfo } from '../models/user.model';
import { environment } from '../../../environments/environment';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private http = inject(HttpClient);
  private router = inject(Router);

  // Signals for reactive state management
  private _currentUser = signal<User | null>(null);
  private _isLoading = signal<boolean>(false);
  private _isInitialized = signal<boolean>(false);
  private _initializationPromise: Promise<void> | null = null;

  // Public readonly signals
  readonly currentUser = this._currentUser.asReadonly();
  readonly isLoading = this._isLoading.asReadonly();
  readonly isInitialized = this._isInitialized.asReadonly();

  // Computed signals
  readonly isAuthenticated = computed(() => !!this._currentUser());
  readonly userRole = computed(() => this._currentUser()?.role || null);
  readonly userPermissions = computed(() => this._currentUser()?.permissions || []);

  constructor() {
    // Don't initialize immediately to avoid circular dependency
    // Manual initialization will be called when needed
  }

  /**
   * Manual initialization method that can be called after app startup
   * Returns the same promise if already initializing to prevent duplicate calls
   */
  initialize(): Promise<void> {
    if (this._isInitialized()) {
      return Promise.resolve();
    }

    if (this._initializationPromise) {
      return this._initializationPromise;
    }

    this._initializationPromise = this.initializeAuth();
    return this._initializationPromise;
  }

  /**
   * Initialize authentication state
   */
  private async initializeAuth(): Promise<void> {
    // Skip initialization if already in progress or completed
    if (this._isLoading() || this._isInitialized()) {
      return;
    }

    this._isLoading.set(true);
    console.log('AuthService: Initializing authentication...');

    try {
      const sessionInfo = await this.getSessionInfo().toPromise();
      console.log('AuthService: Session info received:', sessionInfo);

      if (sessionInfo?.isAuthenticated && sessionInfo.user) {
        this._currentUser.set(sessionInfo.user);
        console.log('AuthService: User authenticated:', sessionInfo.user);
      } else {
        console.log('AuthService: No authenticated user found');
      }
    } catch (error) {
      console.error('AuthService: Failed to initialize auth:', error);
    } finally {
      this._isLoading.set(false);
      this._isInitialized.set(true);
      this._initializationPromise = null;
      console.log('AuthService: Initialization complete');
    }
  }

  /**
   * Get current session information from backend
   */
  getSessionInfo(): Observable<SessionInfo | null> {
    console.log('AuthService: Making session request to:', `${environment.apiUrl}/auth/session`);
    return this.http.get<SessionInfo>(`${environment.apiUrl}/auth/session`, {
      withCredentials: true  // Ensure cookies are sent
    }).pipe(
      tap(sessionInfo => {
        console.log('AuthService: Session response received:', sessionInfo);
      }),
      catchError(error => {
        console.error('AuthService: Session info error:', error);
        return of(null);
      })
    );
  }

  /**
   * Initiate login (redirect to SSO)
   */
  login(returnTo?: string): void {
    const params = new URLSearchParams();
    if (returnTo) {
      params.append('returnTo', returnTo);
    }

    const loginUrl = `${environment.apiUrl}/auth/login${params.toString() ? '?' + params.toString() : ''}`;
    window.location.href = loginUrl;
  }

  /**
   * Logout user
   */
  logout(): Observable<any> {
    this._isLoading.set(true);

    return this.http.post(`${environment.apiUrl}/auth/logout`, {}).pipe(
      tap((response: any) => {
        this._currentUser.set(null);

        // If there's a logout URL from SSO, redirect there
        if (response.redirectUrl) {
          window.location.href = response.redirectUrl;
        }
      }),
      catchError(error => {
        console.error('Logout error:', error);
        // Clear user state even if logout fails
        this._currentUser.set(null);
        return throwError(() => error);
      }),
      tap(() => this._isLoading.set(false))
    );
  }

  /**
   * Check if user has specific permission
   */
  hasPermission(permission: string): boolean {
    const permissions = this.userPermissions();
    return permissions.includes(permission);
  }

  /**
   * Check if user has any of the specified roles
   */
  hasRole(roles: string | string[]): boolean {
    const userRole = this.userRole();
    if (!userRole) return false;

    const roleArray = Array.isArray(roles) ? roles : [roles];
    return roleArray.includes(userRole);
  }

  /**
   * Check if user has admin access
   */
  isAdmin(): boolean {
    return this.hasRole('admin');
  }

  /**
   * Check if user has moderator or admin access
   */
  isModerator(): boolean {
    return this.hasRole(['admin', 'moderator']);
  }

  /**
   * Refresh user session
   */
  refreshSession(): Observable<SessionInfo | null> {
    this._isLoading.set(true);

    return this.getSessionInfo().pipe(
      tap(sessionInfo => {
        if (sessionInfo?.isAuthenticated && sessionInfo.user) {
          this._currentUser.set(sessionInfo.user);
        } else {
          this._currentUser.set(null);
        }
        this._isLoading.set(false);
      }),
      catchError(error => {
        this._isLoading.set(false);
        this._currentUser.set(null);
        return throwError(() => error);
      })
    );
  }
}
