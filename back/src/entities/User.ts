import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
  ManyToMany,
  JoinTable,
} from 'typeorm';
import { Role } from './Role';

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
  nni: string; // National Number Identifier - stores OIDC sub

  @Column({ unique: true })
  @Index()
  email: string;

  @Column()
  firstName: string;

  @Column()
  lastName: string;

  // Keep old role column for backward compatibility during migration
  @Column({
    type: 'enum',
    enum: UserRole,
    default: UserRole.USER,
    nullable: true,
  })
  role?: UserRole;

  // New many-to-many relationship with roles
  @ManyToMany(() => Role, (role: Role) => role.users, { eager: true })
  @JoinTable({
    name: 'user_roles',
    joinColumn: { name: 'userId', referencedColumnName: 'id' },
    inverseJoinColumn: { name: 'roleId', referencedColumnName: 'id' }
  })
  roles: Role[];

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

  // Current role (single role business logic)
  get currentRole(): Role | null {
    if (!this.roles || this.roles.length === 0) return null;
    return this.roles[0] || null; // For now, just return the first role
  }

  get currentRoleName(): string | null {
    return this.currentRole?.name || null;
  }

  // All permissions from roles
  get allPermissions(): any[] {
    if (!this.roles) return [];
    return this.roles
      .filter(role => role.isActive)
      .flatMap(role => role.permissions || [])
      .filter(permission => permission.isActive);
  }

  // Check if user has a specific permission
  hasPermission(requiredPermission: string): boolean {
    return this.allPermissions.some(permission => permission.matches(requiredPermission));
  }

  // Check if user has a specific role
  hasRole(roleName: string): boolean {
    return this.roles?.some(role => role.name === roleName) || false;
  }

  // Assign single role (current business logic)
  assignRole(role: Role): void {
    this.roles = [role];
  }

  // Get profile freshness info (based on last login)
  get profileAge(): number {
    if (!this.lastLoginAt) return Infinity;
    return Date.now() - this.lastLoginAt.getTime();
  }
}
