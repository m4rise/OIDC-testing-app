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

  // Method to check if user has permission
  hasPermission(permission: string): boolean {
    const rolePermissions = {
      [UserRole.ADMIN]: ['read', 'write', 'delete', 'admin'],
      [UserRole.MODERATOR]: ['read', 'write', 'moderate'],
      [UserRole.USER]: ['read'],
    };

    return rolePermissions[this.role]?.includes(permission) ?? false;
  }
}
