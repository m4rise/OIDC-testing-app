import { Request } from 'express';
import { UserRepository } from '../repositories/UserRepository';
import { User } from '../entities/User';

export interface SessionInfo {
  user: {
    id: string;
    email: string;
    firstName: string;
    lastName: string;
    fullName: string;
    role: string;
    isActive: boolean;
    permissions: string[];
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
          email: '',
          firstName: '',
          lastName: '',
          fullName: '',
          role: '',
          isActive: false,
          permissions: [],
        },
        isAuthenticated: false,
      };
    }

    const user = req.user as User;

    // Get fresh user data from database
    const freshUser = await this.userRepository.findById(user.id);
    if (!freshUser) {
      return null;
    }

    // Get user permissions based on role
    const permissions = this.getUserPermissions(freshUser.role);

    return {
      user: {
        id: freshUser.id,
        email: freshUser.email,
        firstName: freshUser.firstName,
        lastName: freshUser.lastName,
        fullName: freshUser.fullName,
        role: freshUser.role,
        isActive: freshUser.isActive,
        permissions,
      },
      isAuthenticated: true,
    };
  }

  async updateLastLogin(userId: string): Promise<void> {
    await this.userRepository.updateLastLogin(userId);
  }

  private getUserPermissions(role: string): string[] {
    const rolePermissions = {
      admin: ['read', 'write', 'delete', 'admin'],
      moderator: ['read', 'write', 'moderate'],
      user: ['read'],
    };

    return rolePermissions[role as keyof typeof rolePermissions] || [];
  }

  generateOIDCState(): string {
    return Math.random().toString(36).substring(2, 15) +
           Math.random().toString(36).substring(2, 15);
  }

  generateOIDCNonce(): string {
    return Math.random().toString(36).substring(2, 15) +
           Math.random().toString(36).substring(2, 15);
  }
}
