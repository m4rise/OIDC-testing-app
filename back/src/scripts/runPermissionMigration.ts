#!/usr/bin/env node

/**
 * Permission Migration Runner
 *
 * This script executes the role and permission migration to the new wildcard-based system.
 * It preserves your existing matchesPermission logic while adding hierarchical capabilities.
 */

import "reflect-metadata";
import { AppDataSource } from "../data-source";
import { OptimizedPermissionMigrator } from "./migrateRolePermissions";
import * as fs from 'fs';
import * as path from 'path';

async function runMigration() {
  console.log('🚀 Starting Permission System Migration');
  console.log('=' .repeat(50));

  try {
    // Initialize the database connection
    console.log('📦 Initializing database connection...');
    await AppDataSource.initialize();
    console.log('✅ Database connected successfully');

    // Create migrator instance with DataSource
    const migrator = new OptimizedPermissionMigrator(AppDataSource);

    // Load old permissions data - you'll need to create this file with your old data
    const oldDataPath = path.join(__dirname, 'oldPermissionsData.json');
    let oldRoleStructure = {};

    if (fs.existsSync(oldDataPath)) {
      const oldDataContent = fs.readFileSync(oldDataPath, 'utf8');
      oldRoleStructure = JSON.parse(oldDataContent);
      console.log('📄 Loaded old permissions data from file');
    } else {
      console.log('⚠️  No old permissions data file found. Creating example structure...');
      // You can replace this with your actual old structure
      oldRoleStructure = {
        admin: {
          consultation: { annuaire: true, installation: true, referentiel_technique: true },
          outils: { support_service: true },
          catalogue: true,
          administration: true,
          documentation: true
        },
        user: {
          consultation: { annuaire: true },
          catalogue: true,
          documentation: true
        }
      };
    }

    // Run the migration
    console.log('🔄 Starting permission migration...');
    await migrator.migrate(oldRoleStructure);

    console.log('=' .repeat(50));
    console.log('🎉 Migration completed successfully!');
    console.log('');
    console.log('Next steps:');
    console.log('1. Update your frontend route guards to use route: permissions');
    console.log('2. Update your backend API endpoints to use api: permissions');
    console.log('3. Test the new permission system with your existing matchesPermission logic');
    console.log('4. Remove old permissions once everything is validated');

  } catch (error) {
    console.error('❌ Migration failed:', error);
    process.exit(1);
  } finally {
    // Close database connection
    if (AppDataSource.isInitialized) {
      await AppDataSource.destroy();
      console.log('📦 Database connection closed');
    }
  }
}

// Run the migration if this file is executed directly
if (require.main === module) {
  runMigration().catch(error => {
    console.error('💥 Fatal error:', error);
    process.exit(1);
  });
}

export { runMigration };
