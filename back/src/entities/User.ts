import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
} from 'typeorm';

export enum UserRole {
  ADMIN = 'admin',
  USER = 'user',
  MODERATOR = 'moderator',
}

@Entity('users')
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  @Index()
  email: string;

  @Column()
  firstName: string;

  @Column()
  lastName: string;

  @Column({
    type: 'enum',
    enum: UserRole,
    default: UserRole.USER,
  })
  role: UserRole;

  @Column({ nullable: true })
  @Index()
  oidcSubject: string;

  @Column({ nullable: true })
  oidcIssuer: string;

  @Column({ type: 'jsonb', nullable: true })
  oidcProfile: Record<string, any>;

  @Column({ default: true })
  isActive: boolean;

  @Column({ nullable: true })
  lastLoginAt: Date;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  // Virtual property to get full name
  get fullName(): string {
    return `${this.firstName} ${this.lastName}`;
  }

  // Method to check if user has permission (enhanced with OIDC)
  hasPermission(permission: string): boolean {
    // Check local role permissions
    const rolePermissions = {
      [UserRole.ADMIN]: ['read', 'write', 'delete', 'admin'],
      [UserRole.MODERATOR]: ['read', 'write', 'moderate'],
      [UserRole.USER]: ['read'],
    };

    const localPermissions = rolePermissions[this.role] || [];
    if (localPermissions.includes(permission)) {
      return true;
    }

    // Check OIDC profile permissions if available
    if (this.oidcProfile) {
      const oidcPermissions = this.getOIDCPermissions();
      if (oidcPermissions.includes(permission)) {
        return true;
      }

      // Check OIDC groups (treat groups as permissions)
      const groups = this.oidcProfile.groups || [];
      if (Array.isArray(groups) && groups.includes(permission)) {
        return true;
      }
    }

    return false;
  }

  // Extract permissions from OIDC profile
  private getOIDCPermissions(): string[] {
    if (!this.oidcProfile) return [];

    const permissions: string[] = [];

    // From groups claim
    if (this.oidcProfile.groups && Array.isArray(this.oidcProfile.groups)) {
      permissions.push(...this.oidcProfile.groups);
    }

    // From roles claim
    if (this.oidcProfile.roles && Array.isArray(this.oidcProfile.roles)) {
      permissions.push(...this.oidcProfile.roles);
    }

    // From custom permissions claim
    if (this.oidcProfile.permissions && Array.isArray(this.oidcProfile.permissions)) {
      permissions.push(...this.oidcProfile.permissions);
    }

    return [...new Set(permissions)]; // Remove duplicates
  }

  // Get profile freshness info
  get profileAge(): number {
    if (!this.lastLoginAt) return Infinity;
    return Date.now() - this.lastLoginAt.getTime();
  }

  get isProfileStale(): boolean {
    const maxAge = 24 * 60 * 60 * 1000; // 24 hours
    return this.profileAge > maxAge;
  }
}
