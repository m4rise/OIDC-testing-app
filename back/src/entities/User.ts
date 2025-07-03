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
  nni: string; // National Number Identifier - stores OIDC sub

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

  // Method to check if user has permission
  hasPermission(permission: string): boolean {
    const rolePermissions = {
      [UserRole.ADMIN]: ['read', 'write', 'delete', 'admin'],
      [UserRole.MODERATOR]: ['read', 'write', 'moderate'],
      [UserRole.USER]: ['read'],
    };

    const userPermissions = rolePermissions[this.role] || [];
    return userPermissions.includes(permission);
  }

  // Get profile freshness info (based on last login)
  get profileAge(): number {
    if (!this.lastLoginAt) return Infinity;
    return Date.now() - this.lastLoginAt.getTime();
  }
}
