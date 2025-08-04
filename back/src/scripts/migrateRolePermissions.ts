#!/usr/bin/env node

/**
 * Unified Permission Migration Script
 *
 * This script migrates your old role/permission structure to the new wildcard-based system.
 * It uses your existing AppDataSource configuration.
 */

import 'reflect-metadata';
import { DataSource } from 'typeorm';
import { AppDataSource } from '../data-source';
import { Role } from '../entities/Role';
import { Permission } from '../entities/Permission';

interface OldRoleStructure {
  [roleName: string]: {
    consultation?: {
      annuaire?: boolean;
      installation?: boolean;
      referentiel_technique?: boolean;
    };
    outils?: {
      support_service?: boolean;
    };
    catalogue?: boolean;
    administration?: boolean;
    documentation?: boolean;
  };
}

class OptimizedPermissionMigrator {
  private dataSource: DataSource;
  private roleRepository: any;
  private permissionRepository: any;

  constructor(dataSource: DataSource) {
    this.dataSource = dataSource;
    this.roleRepository = dataSource.getRepository(Role);
    this.permissionRepository = dataSource.getRepository(Permission);
  }

  /**
   * Génère les permissions optimisées pour les routes Angular
   * Structure hiérarchique basée sur vos anciennes permissions
   */
  private generateOptimizedPermissions(): Array<{name: string, description: string}> {
    return [
      // 🚪 PERMISSIONS ROUTE - Structure hiérarchique du général au particulier
      { name: 'route', description: 'Accès à toutes les routes' },

      // Permissions par domaine (basées sur votre ancienne structure)
      { name: 'route:consultation', description: 'Accès aux pages de consultation' },
      { name: 'route:consultation:annuaire', description: 'Accéder à la page annuaire' },
      { name: 'route:consultation:installation', description: 'Accéder à la page installations' },
      { name: 'route:consultation:referentiel-technique', description: 'Accéder au référentiel technique' },

      { name: 'route:outils', description: 'Accès aux outils' },
      { name: 'route:outils:support-service', description: 'Accéder aux outils de support' },

      { name: 'route:catalogue', description: 'Accéder à la page catalogue' },
      { name: 'route:documentation', description: 'Accéder à la documentation' },
      { name: 'route:administration', description: 'Accéder à l\'administration' },
    ];
  }

  /**
   * Mapping direct de l'ancien système vers les nouvelles permissions route
   * Respecte la hiérarchie du général au particulier
   */
  private mapOldToOptimizedPermissions(oldStructure: OldRoleStructure): { [roleName: string]: string[] } {
    const mapping: { [roleName: string]: string[] } = {};

    for (const [roleName, perms] of Object.entries(oldStructure)) {
      const permissions: string[] = [];

      // 🔍 Consultation - mapping direct
      if (perms.consultation?.annuaire) {
        permissions.push('route:consultation:annuaire');
      }
      if (perms.consultation?.installation) {
        permissions.push('route:consultation:installation');
      }
      if (perms.consultation?.referentiel_technique) {
        permissions.push('route:consultation:referentiel-technique');
      }

      // Si toutes les consultations → optimiser avec permission plus générale
      const hasAllConsultations = perms.consultation?.annuaire &&
                                 perms.consultation?.installation &&
                                 perms.consultation?.referentiel_technique;
      if (hasAllConsultations) {
        // Remplacer par permission plus générale
        const consultationPerms = permissions.filter(p => p.startsWith('route:consultation:'));
        if (consultationPerms.length >= 3) {
          permissions.splice(0, permissions.length, ...permissions.filter(p => !p.startsWith('route:consultation:')));
          permissions.push('route:consultation');
        }
      }

      // � Outils
      if (perms.outils?.support_service) {
        permissions.push('route:outils:support-service');
      }

      // � Catalogue
      if (perms.catalogue) {
        permissions.push('route:catalogue');
      }

      // � Documentation
      if (perms.documentation) {
        permissions.push('route:documentation');
      }

      // 🛠️ Administration
      if (perms.administration) {
        permissions.push('route:administration');
      }

      // 🎯 Permissions spéciales selon le niveau du rôle
      switch (roleName) {
        case 'ADMINISTRATEUR':
          // Admin = accès à tout (permission la plus générale)
          permissions.length = 0;
          permissions.push('route');
          break;

        default:
          // Autres rôles gardent leurs permissions spécifiques basées sur l'ancienne structure
          break;
      }

      mapping[roleName] = [...new Set(permissions)];
    }

    return mapping;
  }

  /**
   * Migration complète
   */
  async migrate(oldStructure: OldRoleStructure): Promise<void> {
    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      console.log('🔄 Starting optimized permission migration...');

      // 1. Créer toutes les permissions
      const allPermissions = this.generateOptimizedPermissions();

      console.log(`📝 Creating ${allPermissions.length} permissions...`);
      for (const permData of allPermissions) {
        let permission = await queryRunner.manager.findOne(Permission, {
          where: { name: permData.name }
        });

        if (!permission) {
          permission = queryRunner.manager.create(Permission, {
            name: permData.name,
            description: permData.description,
            isActive: true,
            createdAt: new Date(),
            updatedAt: new Date(),
          });
          await queryRunner.manager.save(permission);
          console.log(`  ✅ Created: ${permData.name}`);
        } else {
          permission.description = permData.description;
          await queryRunner.manager.save(permission);
          console.log(`  🔄 Updated: ${permData.name}`);
        }
      }

      // 2. Mapper et assigner aux rôles
      const roleMapping = this.mapOldToOptimizedPermissions(oldStructure);

      console.log('👥 Processing roles...');
      for (const [roleName, permissionNames] of Object.entries(roleMapping)) {
        let role = await queryRunner.manager.findOne(Role, {
          where: { name: roleName },
          relations: ['permissions']
        });

        if (!role) {
          console.log(`  📋 Creating new role: ${roleName}`);
          role = queryRunner.manager.create(Role, {
            name: roleName,
            description: `Role ${roleName} migrated with optimized permissions`,
            isActive: true,
            createdAt: new Date(),
            updatedAt: new Date(),
            permissions: []
          });
          await queryRunner.manager.save(role);
        }

        // Vider les permissions actuelles
        role.permissions = [];

        // Assigner les nouvelles permissions
        const newPermissions: Permission[] = [];
        for (const permissionName of permissionNames) {
          const permission = await queryRunner.manager.findOne(Permission, {
            where: { name: permissionName }
          });

          if (permission) {
            newPermissions.push(permission);
          } else {
            console.warn(`  ⚠️ Permission not found: ${permissionName}`);
          }
        }

        role.permissions = newPermissions;
        role.updatedAt = new Date();
        await queryRunner.manager.save(role);

        // Affichage détaillé
        const routePerms = permissionNames.filter(p => p.startsWith('route:'));

        console.log(`  ✅ ${roleName} (${newPermissions.length} permissions):`);
        if (routePerms.length > 0) {
          console.log(`     🚪 Routes: ${routePerms.join(', ')}`);
        } else {
          console.log(`     � Routes: Aucune permission route`);
        }
      }

      await queryRunner.commitTransaction();
      console.log('🎉 Migration completed successfully!');

      // Afficher un résumé
      await this.displaySummary();

    } catch (error) {
      await queryRunner.rollbackTransaction();
      console.error('❌ Migration failed:', error);
      throw error;
    } finally {
      await queryRunner.release();
    }
  }

  /**
   * Affichage du résumé final - focalisé sur les permissions route
   */
  private async displaySummary(): Promise<void> {
    console.log('\n=== RÉSUMÉ DE LA MIGRATION (ROUTES) ===');

    const roles = await this.roleRepository.find({
      relations: ['permissions'],
      order: { name: 'ASC' }
    });

    for (const role of roles) {
      console.log(`\n📋 ${role.name}:`);

      const routePermissions = role.permissions
        .filter((perm: Permission) => perm.name.startsWith('route:'))
        .map((perm: Permission) => perm.name)
        .sort();

      if (routePermissions.length > 0) {
        console.log(`   🚪 Routes (${routePermissions.length}):`);
        routePermissions.forEach((perm: string) => console.log(`      - ${perm}`));
      } else {
        console.log('   - Aucune permission route');
      }
    }
  }

  /**
   * Obtient la structure des anciens rôles
   * Basée sur votre système existant
   */
  private getOldRoleStructure(): OldRoleStructure {
    return {
      'ADMINISTRATEUR': {
        consultation: { annuaire: true, installation: true, referentiel_technique: true },
        outils: { support_service: true },
        catalogue: true,
        administration: true,
        documentation: true
      },
      'CCN MULTIMEDIA': {
        consultation: { annuaire: true, installation: true, referentiel_technique: true },
        outils: { support_service: true },
        catalogue: true,
        documentation: true
      },
      'CHEF DE PROJET': {
        consultation: { annuaire: true, installation: true, referentiel_technique: true },
        catalogue: true,
        documentation: true
      },
      'SSE': {
        consultation: { annuaire: true, installation: true, referentiel_technique: true },
        documentation: true
      },
      'SSESANSMDP': {
        consultation: { annuaire: true, installation: true },
        documentation: true
      },
      'MOA': {
        consultation: { annuaire: true },
        catalogue: true,
        documentation: true
      }
    };
  }

  /**
   * Migration avec la structure de données intégrée
   */
  async migrateFromOldStructure(): Promise<void> {
    console.log('📖 Using integrated old role structure...');
    const oldStructure = this.getOldRoleStructure();
    await this.migrate(oldStructure);
  }
}

/**
 * Fonction principale de migration
 */
async function runPermissionMigration(): Promise<void> {
  console.log('🚀 Starting Unified Permission Migration');
  console.log('=' .repeat(50));

  try {
    // Utiliser votre DataSource existant
    console.log('📦 Initializing database connection using AppDataSource...');
    await AppDataSource.initialize();
    console.log('✅ Database connected successfully');

    // Créer l'instance de migration
    const migrator = new OptimizedPermissionMigrator(AppDataSource);

    // Lancer la migration avec les données intégrées
    console.log('📄 Using integrated old permissions data...');
    await migrator.migrateFromOldStructure();

    console.log('=' .repeat(50));
    console.log('🎉 Migration completed successfully!');
    console.log('');
    console.log('Next steps:');
    console.log('1. Update your frontend route guards to use the new route: permissions');
    console.log('2. The Angular permission guards will now work with the hierarchical system');
    console.log('3. Test the new permission system with your existing matchesPermission logic');
    console.log('4. API permissions should be handled separately from route permissions');

  } catch (error) {
    console.error('❌ Migration failed:', error);
    throw error;
  } finally {
    // Fermer la connexion
    if (AppDataSource.isInitialized) {
      await AppDataSource.destroy();
      console.log('� Database connection closed');
    }
  }
}

// Exécution si lancé directement
if (require.main === module) {
  runPermissionMigration()
    .then(() => {
      console.log('\n✨ Migration terminée avec succès !');
      process.exit(0);
    })
    .catch((error) => {
      console.error('\n💥 Erreur lors de la migration :', error);
      process.exit(1);
    });
}

export { OptimizedPermissionMigrator, runPermissionMigration };
