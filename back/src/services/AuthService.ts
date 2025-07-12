import { Request } from 'express';
import { UserRepository } from '../repositories/UserRepository';
import { User, UserRole } from '../entities/User';
import { config } from '../config/environment';

export interface SessionInfo {
  user: {
    id: string;
    nni: string;  // OIDC sub stored as nni
    email: string;
    firstName: string;
    lastName: string;
    fullName: string;
    role: string;
    isActive: boolean;
    permissions: string[];
    createdAt: string;
    lastLoginAt?: string;
  };
  isAuthenticated: boolean;
}

export class AuthService {
  private userRepository: UserRepository;

  constructor() {
    this.userRepository = new UserRepository();
  }

  async getSessionInfo(req: Request): Promise<SessionInfo | null> {
    if (!req.isAuthenticated() || !req.user) {
      return {
        user: {
          id: '',
          nni: '',
          email: '',
          firstName: '',
          lastName: '',
          fullName: '',
          role: '',
          isActive: false,
          permissions: [],
          createdAt: new Date().toISOString(),
          lastLoginAt: undefined,
        },
        isAuthenticated: false,
      };
    }

    const user = req.user as User;

    // Get fresh user data from database (works for both real and dynamically created mock users)
    const freshUser = await this.userRepository.findById(user.id);
    if (!freshUser) {
      return null;
    }

    // Get user permissions based on role
    const permissions = this.getUserPermissions(freshUser.role);

    return {
      user: {
        id: freshUser.id,
        nni: freshUser.nni,
        email: freshUser.email,
        firstName: freshUser.firstName,
        lastName: freshUser.lastName,
        fullName: freshUser.fullName,
        role: freshUser.role,
        isActive: freshUser.isActive,
        permissions,
        createdAt: freshUser.createdAt?.toISOString() || new Date().toISOString(),
        lastLoginAt: freshUser.lastLoginAt?.toISOString(),
      },
      isAuthenticated: true,
    };
  }

  private getUserPermissions(role: string): string[] {
    const rolePermissions = {
      admin: ['read', 'write', 'delete', 'admin'],
      moderator: ['read', 'write', 'moderate'],
      user: ['read'],
    };

    return rolePermissions[role as keyof typeof rolePermissions] || [];
  }
}
