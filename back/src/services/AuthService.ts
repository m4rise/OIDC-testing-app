import { Request } from 'express';
import { UserRepository } from '../repositories/UserRepository';
import { User, UserRole } from '../entities/User';

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

  async findOrCreateUserFromOIDC(userInfo: {
    email: string;
    firstName: string;
    lastName: string;
    sub: string;
    oidcIssuer?: string;
  }): Promise<User> {
    const oidcIssuer = userInfo.oidcIssuer || 'mock-oidc';

    // First try to find existing user by OIDC subject (primary identifier)
    let user = await this.userRepository.findByOIDC(userInfo.sub, oidcIssuer);

    if (!user) {
      // Fallback: try to find by email if user doesn't exist with OIDC subject
      const existingUser = await this.userRepository.findByEmail(userInfo.email);
      if (existingUser) {
        // Update existing user with OIDC information
        await this.userRepository.update(existingUser.id, {
          oidcSubject: userInfo.sub,
          oidcIssuer: oidcIssuer,
          lastLoginAt: new Date()
        });
        // Refetch the updated user
        user = await this.userRepository.findById(existingUser.id) || existingUser;
      } else {
        // Create new user with default role based on email
        const defaultRole = this.getDefaultRoleForEmail(userInfo.email);
        user = await this.userRepository.create({
          email: userInfo.email,
          firstName: userInfo.firstName,
          lastName: userInfo.lastName,
          role: defaultRole,
          oidcSubject: userInfo.sub,
          oidcIssuer: oidcIssuer,
          isActive: true,
          lastLoginAt: new Date(),
        });

        console.log(`✅ Created new user from OIDC: ${user.email} with role: ${user.role}`);
      }
    } else {
      // Update existing OIDC user's last login
      await this.userRepository.update(user.id, {
        lastLoginAt: new Date()
      });
      user = await this.userRepository.findById(user.id) || user;
    }

    return user;
  }

  private getDefaultRoleForEmail(email: string): UserRole {
    // Define admin emails for mock development
    const adminEmails = ['admin@example.com'];
    const moderatorEmails = ['manager@example.com'];

    if (adminEmails.includes(email.toLowerCase())) {
      return UserRole.ADMIN;
    }
    if (moderatorEmails.includes(email.toLowerCase())) {
      return UserRole.MODERATOR;
    }
    return UserRole.USER; // Default role
  }
}
