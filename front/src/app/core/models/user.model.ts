export interface User {
  id: string;
  nni: string; // OIDC sub stored as nni
  email: string;
  firstName: string;
  lastName: string;
  fullName: string;
  roles: string[]; // RBAC roles array
  currentRole: string; // Current active role
  permissions: string[]; // Flattened permissions from all roles
  isActive: boolean;
  createdAt: string;
  lastLoginAt?: string;
}

export interface SessionInfo {
  user: User;
  isAuthenticated: boolean;
  totalPermissions?: number;
}

// For backward compatibility in some places
export type UserRole = 'admin' | 'moderator' | 'user';

export interface ApiResponse<T = any> {
  data?: T;
  error?: string;
  message?: string;
}

export interface PaginatedResponse<T> {
  users?: T[];
  data?: T[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
}

export interface CreateUserDto {
  email: string;
  firstName: string;
  lastName: string;
  role?: string; // Now accepts role name
}

export interface UpdateUserDto {
  firstName?: string;
  lastName?: string;
  role?: string; // Now accepts role name
  isActive?: boolean;
}
