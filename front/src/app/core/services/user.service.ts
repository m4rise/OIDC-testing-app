import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

import { User, PaginatedResponse, CreateUserDto, UpdateUserDto } from '../models/user.model';
import { environment } from '../../../environments/environment';

@Injectable({
  providedIn: 'root'
})
export class UserService {
  private http = inject(HttpClient);

  /**
   * Get current user profile
   */
  getProfile(): Observable<User> {
    return this.http.get<User>(`${environment.apiUrl}/users/profile`);
  }

  /**
   * Update current user profile
   */
  updateProfile(userId: string, userData: UpdateUserDto): Observable<User> {
    return this.http.put<User>(`${environment.apiUrl}/users/profile`, userData);
  }

  /**
   * Get all users (admin/moderator only)
   */
  getUsers(params?: {
    page?: number;
    limit?: number;
    role?: string;
    isActive?: boolean;
  }): Observable<PaginatedResponse<User>> {
    return this.http.get<PaginatedResponse<User>>(`${environment.apiUrl}/users`, {
      params: params as any
    });
  }

  /**
   * Get user by ID (admin/moderator only)
   */
  getUserById(id: string): Observable<User> {
    return this.http.get<User>(`${environment.apiUrl}/users/${id}`);
  }

  /**
   * Create new user (admin only)
   */
  createUser(userData: CreateUserDto): Observable<User> {
    return this.http.post<User>(`${environment.apiUrl}/users`, userData);
  }

  /**
   * Update user (admin only)
   */
  updateUser(id: string, userData: UpdateUserDto): Observable<User> {
    return this.http.put<User>(`${environment.apiUrl}/users/${id}`, userData);
  }

  /**
   * Delete user (admin only)
   */
  deleteUser(id: string): Observable<{ success: boolean; message: string }> {
    return this.http.delete<{ success: boolean; message: string }>(`${environment.apiUrl}/users/${id}`);
  }

  /**
   * Get user statistics (admin only)
   */
  getUserStats(): Observable<{
    total: number;
    byRole: Record<string, number>;
    active: number;
    inactive: number;
  }> {
    return this.http.get<{
      total: number;
      byRole: Record<string, number>;
      active: number;
      inactive: number;
    }>(`${environment.apiUrl}/users/stats`);
  }
}
