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
import { User } from '../entities/User';

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
    // 🆕 Définition du niveau d'accès API par rôle
    apiLevel?: 'read' | 'write' | 'delete' | 'export' | 'support-service' | 'administration';
    // 🆕 Domaines API spécifiques (optionnel)
    apiDomains?: string[];
  };
}

// 🆕 Configuration des niveaux d'accès par rôle
interface RoleApiConfig {
  permissions: Array<{
    domains: string[];
    level: 'read' | 'write' | 'delete' | 'export' | 'support-service' | 'administration';
  }>;
  description: string;
}

class OptimizedPermissionMigrator {
  private dataSource: DataSource;
  private roleRepository: any;
  private permissionRepository: any;
  private userRepository: any;

  constructor(dataSource: DataSource) {
    this.dataSource = dataSource;
    this.roleRepository = dataSource.getRepository(Role);
    this.permissionRepository = dataSource.getRepository(Permission);
    this.userRepository = dataSource.getRepository(User);
  }

  /**
   * 🆕 Configuration des accès API par rôle
   * Permet des niveaux multiples et des domaines différents
   */
  private getRoleApiConfiguration(): { [roleName: string]: RoleApiConfig } {
    return {
      'ADMINISTRATEUR': {
        permissions: [
          { domains: ['*'], level: 'administration' } // Administration globale
        ],
        description: 'Accès administration complet à toutes les API'
      },
      'CCN MULTIMEDIA': {
        permissions: [
          { domains: ['*'], level: 'administration' }, // Administration globale
        ],
        description: 'Administration complète sur toutes les API (technique avancé)'
      },
      'CHEF DE PROJET': {
        permissions: [
          { domains: ['contact', 'project'], level: 'write' }, // Écriture sur contact et projet
          { domains: ['user'], level: 'read' }, // Lecture sur user
          { domains: ['media'], level: 'delete' } // Peut supprimer des médias
        ],
        description: 'Écriture sur projets/contacts, lecture sur utilisateurs, suppression médias'
      },
      'SSE': {
        permissions: [
          { domains: ['*'], level: 'read' }, // Lecture globale
          { domains: ['system', 'security'], level: 'administration' }, // Administration sécurité
          { domains: ['support'], level: 'support-service' } // Support service
        ],
        description: 'Lecture globale + administration sécurité + support service'
      },
      'SSESANSMDP': {
        permissions: [
          { domains: ['contact'], level: 'read' },
          { domains: ['installation'], level: 'write' }, // Peut modifier installations
          { domains: ['system'], level: 'export' } // Peut exporter données système
        ],
        description: 'Lecture contact, écriture installation, export système'
      },
      'MOA': {
        permissions: [
          { domains: ['contact', 'project'], level: 'read' }, // Lecture métier
          { domains: ['documentation'], level: 'write' }, // Peut modifier la doc
          { domains: ['content'], level: 'export' } // Peut exporter le contenu
        ],
        description: 'Lecture contact/projets, écriture documentation, export contenu'
      }
    };
  }

  /**
   * 🆕 Génère les permissions API basées sur les niveaux d'accès
   */
  private generateApiPermissions(): Array<{name: string, description: string}> {
    const permissions: Array<{name: string, description: string}> = [];

    // Permissions globales
    permissions.push(
      { name: 'api', description: 'Accès complet à toutes les API' },
      { name: 'api:*:read', description: 'Lecture simple sur toutes les API' },
      { name: 'api:*:write', description: 'Écriture simple sur toutes les API' },
      { name: 'api:*:delete', description: 'Suppression sur toutes les API' },
      { name: 'api:*:export', description: 'Export de données sur toutes les API' },
      { name: 'api:*:support-service', description: 'Support service sur toutes les API' },
      { name: 'api:*:administration', description: 'Administration sur toutes les API' }
    );

    // Domaines actifs (ajoutez selon vos besoins)
    const activeDomains = ['contact', 'user', 'project', 'media', 'content', 'installation', 'system', 'security', 'support', 'documentation'];

    for (const domain of activeDomains) {
      permissions.push(
        { name: `api:${domain}`, description: `Accès complet API ${domain}` },
        { name: `api:${domain}:read`, description: `Lecture simple ${domain}` },
        { name: `api:${domain}:write`, description: `Écriture simple ${domain}` },
        { name: `api:${domain}:delete`, description: `Suppression ${domain}` },
        { name: `api:${domain}:export`, description: `Export de données ${domain}` },
        { name: `api:${domain}:support-service`, description: `Support service ${domain}` },
        { name: `api:${domain}:administration`, description: `Administration ${domain}` }
      );
    }

    return permissions;
  }

  /**
   * 🆕 Combine toutes les permissions (route + API)
   */
  private generateAllPermissions(): Array<{name: string, description: string}> {
    return [
      ...this.generateOptimizedPermissions(), // Permissions route existantes
      ...this.generateApiPermissions()        // Nouvelles permissions API
    ];
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
   * 🔄 Mapping étendu avec permissions API granulaires
   * Respecte la hiérarchie du général au particulier
   */
  private mapOldToOptimizedPermissions(oldStructure: OldRoleStructure): { [roleName: string]: string[] } {
    const mapping: { [roleName: string]: string[] } = {};
    const roleApiConfig = this.getRoleApiConfiguration();

    for (const [roleName, perms] of Object.entries(oldStructure)) {
      const permissions: string[] = [];

      // ✅ PERMISSIONS ROUTE (logique existante)
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

      // 🔧 Outils
      if (perms.outils?.support_service) {
        permissions.push('route:outils:support-service');
      }

      // 📋 Catalogue
      if (perms.catalogue) {
        permissions.push('route:catalogue');
      }

      // 📚 Documentation
      if (perms.documentation) {
        permissions.push('route:documentation');
      }

      // 🛠️ Administration
      if (perms.administration) {
        permissions.push('route:administration');
      }

      // 🆕 PERMISSIONS API basées sur la configuration du rôle
      const apiConfig = roleApiConfig[roleName];
      if (apiConfig) {
        // Traiter chaque permission du rôle
        for (const permConfig of apiConfig.permissions) {
          const { domains, level } = permConfig;

          if (domains.includes('*')) {
            // Accès global
            switch (level) {
              case 'administration':
                permissions.push('api:*:administration');
                break;
              case 'support-service':
                permissions.push('api:*:support-service');
                break;
              case 'export':
                permissions.push('api:*:export');
                break;
              case 'delete':
                permissions.push('api:*:delete');
                break;
              case 'write':
                permissions.push('api:*:write');
                break;
              case 'read':
                permissions.push('api:*:read');
                break;
            }
          } else {
            // Accès par domaine spécifique
            for (const domain of domains) {
              switch (level) {
                case 'administration':
                  permissions.push(`api:${domain}:administration`);
                  break;
                case 'support-service':
                  permissions.push(`api:${domain}:support-service`);
                  break;
                case 'export':
                  permissions.push(`api:${domain}:export`);
                  break;
                case 'delete':
                  permissions.push(`api:${domain}:delete`);
                  break;
                case 'write':
                  permissions.push(`api:${domain}:write`);
                  break;
                case 'read':
                  permissions.push(`api:${domain}:read`);
                  break;
              }
            }
          }
        }
      }

      // 🎯 Permissions spéciales selon le niveau du rôle
      switch (roleName) {
        case 'ADMINISTRATEUR':
          // Admin = accès à tout (permission la plus générale)
          permissions.length = 0;
          permissions.push('route', 'api');
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
      console.log('🔄 Starting complete migration (routes + API)...');

      // 1. Créer toutes les permissions (route + API)
      const allPermissions = this.generateAllPermissions();

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
            description: `Role ${roleName} migrated with route and API permissions`,
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
        const apiPerms = permissionNames.filter(p => p.startsWith('api:'));

        console.log(`  ✅ ${roleName} (${newPermissions.length} permissions):`);
        if (routePerms.length > 0) {
          console.log(`     🚪 Routes: ${routePerms.join(', ')}`);
        }
        if (apiPerms.length > 0) {
          console.log(`     🔌 API: ${apiPerms.join(', ')}`);
        }
        if (routePerms.length === 0 && apiPerms.length === 0) {
          console.log(`     ⚠️ Aucune permission`);
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
   * 🔄 Affichage du résumé final - routes et API
   */
  private async displaySummary(): Promise<void> {
    console.log('\n=== RÉSUMÉ DE LA MIGRATION (ROUTES + API) ===');

    const roles = await this.roleRepository.find({
      relations: ['permissions'],
      order: { name: 'ASC' }
    });

    const roleApiConfig = this.getRoleApiConfiguration();

    for (const role of roles) {
      console.log(`\n📋 ${role.name}:`);

      // Configuration API pour ce rôle
      const apiConfig = roleApiConfig[role.name];
      if (apiConfig) {
        console.log(`   💬 ${apiConfig.description}`);
        console.log(`   🎯 API Permissions:`);
        for (const permConfig of apiConfig.permissions) {
          const domainsList = permConfig.domains.join(', ');
          console.log(`      - ${permConfig.level.toUpperCase()} sur ${domainsList}`);
        }
      }

      const routePermissions = role.permissions
        .filter((perm: Permission) => perm.name.startsWith('route:'))
        .map((perm: Permission) => perm.name)
        .sort();

      const apiPermissions = role.permissions
        .filter((perm: Permission) => perm.name.startsWith('api:'))
        .map((perm: Permission) => perm.name)
        .sort();

      if (routePermissions.length > 0) {
        console.log(`   🚪 Routes (${routePermissions.length}):`);
        routePermissions.forEach((perm: string) => console.log(`      - ${perm}`));
      }

      if (apiPermissions.length > 0) {
        console.log(`   🔌 API (${apiPermissions.length}):`);
        apiPermissions.forEach((perm: string) => console.log(`      - ${perm}`));
      }

      if (routePermissions.length === 0 && apiPermissions.length === 0) {
        console.log('   - Aucune permission');
      }
    }

    // 🆕 Tableau récapitulatif des niveaux d'accès
    console.log('\n=== NIVEAUX D\'ACCÈS API PAR RÔLE ===');
    console.log('┌─────────────────────┬─────────────────────────────────────────────┐');
    console.log('│ RÔLE                │ PERMISSIONS API                             │');
    console.log('├─────────────────────┼─────────────────────────────────────────────┤');

    for (const [roleName, config] of Object.entries(roleApiConfig)) {
      const role = roleName.padEnd(19);
      let permissionsText = '';

      for (const permConfig of config.permissions) {
        const domainsList = permConfig.domains.join(',');
        permissionsText += `${permConfig.level}:${domainsList} `;
      }

      const permissions = permissionsText.trim().padEnd(43);
      console.log(`│ ${role} │ ${permissions} │`);
    }
    console.log('└─────────────────────┴─────────────────────────────────────────────┘');
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
    console.log('2. Update your backend API endpoints to use the new api: permissions');
    console.log('3. Test the new permission system with your existing matchesPermission logic');
    console.log('4. Use the hierarchical API permissions for granular access control');

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
