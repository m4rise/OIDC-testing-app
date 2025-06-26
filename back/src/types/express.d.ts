/// <reference types="express" />

import { UserRole } from '../entities/User';

declare global {
  namespace Express {
    interface User {
      id: string;
      email: string;
      firstName: string;
      lastName: string;
      role: UserRole;
      isActive: boolean;
      hasPermission: (permission: string) => boolean;
    }
  }
}
