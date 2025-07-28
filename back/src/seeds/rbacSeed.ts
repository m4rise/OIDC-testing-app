import { AppDataSource } from '../data-source';
import { Role } from '../entities/Role';
import { Permission } from '../entities/Permission';
import { User } from '../entities/User';

export async function seedRBACData() {
  await AppDataSource.initialize();

  const roleRepo = AppDataSource.getRepository(Role);
  const permissionRepo = AppDataSource.getRepository(Permission);
  const userRepo = AppDataSource.getRepository(User);

  console.log('🌱 Starting RBAC seed...');

  try {
    // Create permissions
    const permissions = await permissionRepo.save([
      // API permissions - using wildcards
      { name: 'api:user:read:self', description: 'Read own user data' },
      { name: 'api:user:read:*', description: 'Read any user data' },
      { name: 'api:user:write:self', description: 'Update own user data' },
      { name: 'api:user:write:*', description: 'Create/update any user' },
      { name: 'api:user:delete:*', description: 'Delete any user' },
      { name: 'api:user:*', description: 'All user operations' },
      { name: 'api:*', description: 'All API operations' },

      // Route permissions
      { name: 'route:admin', description: 'Access admin routes' },
      { name: 'route:users', description: 'Access user management routes' },
      { name: 'route:*', description: 'Access any route' },

      // UI permissions
      { name: 'ui:admin-button', description: 'Show admin buttons' },
      { name: 'ui:delete-button', description: 'Show delete buttons' },
      { name: 'ui:user-management', description: 'Show user management UI' },
      { name: 'ui:*', description: 'Show any UI elements' },
    ]);

    console.log(`✅ Created ${permissions.length} permissions`);

    // Create roles with permissions
    const userRole = await roleRepo.save({
      name: 'user',
      description: 'Regular user with basic permissions',
      isSystemRole: true,
      permissions: [
        permissions.find(p => p.name === 'api:user:read:self')!,
        permissions.find(p => p.name === 'api:user:write:self')!,
        permissions.find(p => p.name === 'route:dashboard')!,
      ]
    });

    const moderatorRole = await roleRepo.save({
      name: 'moderator',
      description: 'Content moderator with user management',
      isSystemRole: true,
      permissions: [
        permissions.find(p => p.name === 'api:user:read:*')!,
        permissions.find(p => p.name === 'api:user:write:*')!,
        permissions.find(p => p.name === 'route:users')!,
        permissions.find(p => p.name === 'ui:user-management')!,
        permissions.find(p => p.name === 'ui:delete-button')!,
      ]
    });

    const adminRole = await roleRepo.save({
      name: 'admin',
      description: 'System administrator with full access',
      isSystemRole: true,
      permissions: [
        permissions.find(p => p.name === 'api:*')!, // All API operations
        permissions.find(p => p.name === 'route:*')!, // All routes
        permissions.find(p => p.name === 'ui:*')!, // All UI elements
      ]
    });

    console.log('✅ Created 3 roles with permissions');

    console.log('✅ RBAC data seeded successfully');

  } catch (error) {
    console.error('❌ Error seeding RBAC data:', error);
    throw error;
  }
}

// Run if called directly
if (require.main === module) {
  seedRBACData()
    .then(() => {
      console.log('✅ Seed completed');
      process.exit(0);
    })
    .catch((error) => {
      console.error('❌ Seed failed:', error);
      process.exit(1);
    });
}
