import { Request } from 'express';

export interface SessionInfo {
  user: {
    id: string;
    nni: string;  // OIDC sub stored as nni
    email: string;
    firstName: string;
    lastName: string;
    fullName: string;
    roles: string[];
    currentRole: string;
    permissions: string[];
    isActive: boolean;
    createdAt: string;
    lastLoginAt?: string;
  };
  isAuthenticated: boolean;
}

export class AuthService {

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
          roles: [],
          currentRole: '',
          permissions: [],
          isActive: false,
          createdAt: new Date().toISOString(),
          lastLoginAt: undefined,
        },
        isAuthenticated: false,
      };
    }

    const user = req.user as any; // The lightweight user object from deserializeUser

    return {
      user: {
        id: user.id,
        nni: user.nni,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        fullName: user.fullName,
        roles: user.roles || [],
        currentRole: user.currentRole || user.roles?.[0] || '',
        permissions: user.permissions || [],
        isActive: user.isActive,
        createdAt: user.createdAt?.toISOString() || new Date().toISOString(),
        lastLoginAt: user.lastLoginAt?.toISOString(),
      },
      isAuthenticated: true,
    };
  }
}
