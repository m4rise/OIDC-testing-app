import { Injectable, inject } from '@angular/core';
import { AuthService } from './auth.service';

@Injectable({
  providedIn: 'root'
})
export class PermissionService {
  private authService = inject(AuthService);

  /**
   * Check if user has permission for UI elements
   */
  canShowElement(permission: string): boolean {
    return this.authService.hasPermission(`ui:${permission}`);
  }

  /**
   * Check if user can perform API actions
   */
  canPerformAction(action: string): boolean {
    return this.authService.hasPermission(`api:${action}`);
  }

  /**
   * Check if user can access routes
   */
  canAccessRoute(route: string): boolean {
    return this.authService.hasPermission(`route:${route}`);
  }

  /**
   * Get all user permissions
   */
  getUserPermissions(): string[] {
    return this.authService.userPermissions();
  }

  /**
   * Get user roles
   */
  getUserRoles(): string[] {
    return this.authService.userRoles();
  }

  /**
   * Check if user has role
   */
  hasRole(role: string): boolean {
    return this.authService.hasRole(role);
  }

  /**
   * Check if user has any of the specified roles
   */
  hasAnyRole(roles: string[]): boolean {
    return this.authService.hasRole(roles);
  }

  /**
   * Quick checks for common UI permissions
   */
  canCreateUser(): boolean {
    return this.authService.hasPermission('api:user:write:*');
  }

  canEditUser(): boolean {
    return this.authService.hasPermission('api:user:write:*');
  }

  canDeleteUser(): boolean {
    return this.authService.hasPermission('api:user:delete:*');
  }

  canViewUsers(): boolean {
    return this.authService.hasPermission('api:user:read:*');
  }

  canEditProfile(): boolean {
    return this.authService.hasPermission('api:user:write:self');
  }

  canShowAdminTools(): boolean {
    return this.canShowElement('admin-tools');
  }

  canShowDeleteButton(): boolean {
    return this.canShowElement('delete-button');
  }
}
