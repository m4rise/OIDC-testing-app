import { Request } from 'express';
import { UserRepository } from '../repositories/UserRepository';
import { User, UserRole } from '../entities/User';

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



  /**
   * Get default role for a user based on their email
   *
   * SECURITY NOTE: This method only assigns elevated roles (ADMIN/MODERATOR) in development mode.
   * In production, ALL users are created with USER role by default to prevent privilege escalation.
   *
   * Production workflow:
   * 1. User signs up via OIDC → Gets USER role
   * 2. Admin manually promotes user to ADMIN/MODERATOR via admin interface
   *
   * @param email - User's email address
   * @returns UserRole - Always USER in production, email-based roles in development
   */
  public getDefaultRoleForEmail(email: string): UserRole {
    // SECURITY: Only assign special roles based on email in development
    // In production, all users get USER role by default and must be promoted by admin
    const isDevelopment = process.env.NODE_ENV === 'development';
    const isLocalhost = process.env.FRONTEND_URL?.includes('localhost') ||
                       process.env.BACKEND_URL?.includes('localhost');

    if (!isDevelopment || !isLocalhost) {
      console.warn(`🔒 Production/Remote mode: User ${email} created with default USER role. Admin privileges must be granted manually.`);
      return UserRole.USER;
    }

    // Development-only: Assign roles based on well-known test emails
    const adminEmails = ['admin@example.com'];
    const moderatorEmails = ['manager@example.com'];

    if (adminEmails.includes(email.toLowerCase())) {
      console.log(`🔧 Development mode: Assigning ADMIN role to ${email}`);
      return UserRole.ADMIN;
    }
    if (moderatorEmails.includes(email.toLowerCase())) {
      console.log(`🔧 Development mode: Assigning MODERATOR role to ${email}`);
      return UserRole.MODERATOR;
    }

    console.log(`🔧 Development mode: Assigning USER role to ${email}`);
    return UserRole.USER; // Default role
  }
}
