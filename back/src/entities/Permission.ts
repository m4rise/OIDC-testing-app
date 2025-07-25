import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  ManyToMany,
} from 'typeorm';
import { Role } from './Role';

@Entity('permissions')
export class Permission {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true, length: 255 })
  name: string; // "api:user:read:self", "api:user", "route:admin"

  @Column({ type: 'text', nullable: true })
  description?: string;

  @Column({ default: true })
  isActive: boolean;

  @CreateDateColumn()
  createdAt: Date;

  @ManyToMany(() => Role, (role: Role) => role.permissions)
  roles: Role[];

  // Helper method for matching permissions
  matches(requiredPermission: string): boolean {
    const thisParts = this.name.split(':');
    const reqParts = requiredPermission.split(':');

    // Shorter permissions cover longer ones: "api:user" covers "api:user:read:self"
    if (thisParts.length <= reqParts.length) {
      for (let i = 0; i < thisParts.length; i++) {
        if (thisParts[i] !== reqParts[i] && thisParts[i] !== '*') {
          return false;
        }
      }
      return true;
    }

    return false;
  }
}
