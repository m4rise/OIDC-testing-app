import { AppDataSource } from '../data-source';
import { User } from '../entities/User';
import { Role } from '../entities/Role';
import { Permission } from '../entities/Permission';

async function assignAdminRole() {
  try {
    console.log('🔄 Connecting to database...');
    await AppDataSource.initialize();

    const userRepo = AppDataSource.getRepository(User);
    const roleRepo = AppDataSource.getRepository(Role);
    const permissionRepo = AppDataSource.getRepository(Permission);

    // Find the user
    const user = await userRepo.findOne({
      where: { email: 'dev.user@example.com' },
      relations: ['roles']
    });

    if (!user) {
      console.error('❌ User not found with email: dev.user@example.com');
      return;
    }

    console.log(`👤 Found user: ${user.email}`);

    // Check what roles exist
    const existingRoles = await roleRepo.find();
    console.log(`📋 Existing roles: ${existingRoles.map(r => r.name).join(', ')}`);

    // Find or create the admin role
    let adminRole = await roleRepo.findOne({
      where: { name: 'admin' },
      relations: ['permissions']
    });

    if (!adminRole) {
      console.log('🔨 Creating admin role...');

      // Get all permissions that start with 'api:*', 'route:*', 'ui:*'
      const allPermissions = await permissionRepo.find({
        where: [
          { name: 'api:*' },
          { name: 'route:*' },
          { name: 'ui:*' }
        ]
      });

      console.log(`🔑 Found ${allPermissions.length} admin permissions`);

      // Create admin role
      adminRole = roleRepo.create({
        name: 'admin',
        description: 'System administrator with full access',
        isSystemRole: true,
        isActive: true,
        permissions: allPermissions
      });

      await roleRepo.save(adminRole);
      console.log('✅ Created admin role with full permissions');
    }

    // Check if user already has admin role
    const hasAdminRole = user.roles?.some(role => role.name === 'admin');
    if (hasAdminRole) {
      console.log('✅ User already has admin role');
      return;
    }

    // Assign admin role to user
    if (!user.roles) {
      user.roles = [];
    }
    user.roles.push(adminRole);

    await userRepo.save(user);

    console.log(`✅ Successfully assigned admin role to user: ${user.email}`);
    console.log(`📋 User now has ${user.roles.length} role(s)`);
    console.log(`🔑 Admin role has ${adminRole.permissions?.length || 0} permissions`);

  } catch (error) {
    console.error('❌ Error assigning role:', error);
  } finally {
    await AppDataSource.destroy();
  }
}

// Run the script
assignAdminRole().then(() => {
  console.log('🏁 Script completed');
  process.exit(0);
}).catch(error => {
  console.error('💥 Script failed:', error);
  process.exit(1);
});
