import { DataSource } from 'typeorm';
import { Role } from '../entities/Role';
import { Permission } from '../entities/Permission';
import { User } from '../entities/User';
import * as fs from 'fs';
import * as path from 'path';

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
   * Génère les permissions optimisées avec ta logique "du général au spécifique"
   * + wildcards internes pour éviter la duplication
   */
  private generateOptimizedPermissions(): Array<{name: string, description: string}> {
    return [
      // 🚪 PERMISSIONS ROUTE - Structure hiérarchique
      { name: 'route', description: 'Accès à toutes les routes' },
      { name: 'route:read', description: 'Accès à toutes les pages de consultation' },
      { name: 'route:admin', description: 'Accès à toutes les pages d\'administration' },

      // Routes spécifiques de consultation
      { name: 'route:read:annuaire', description: 'Accéder à la page annuaire' },
      { name: 'route:read:installation', description: 'Accéder à la page installations' },
      { name: 'route:read:referentiel-technique', description: 'Accéder au référentiel technique' },
      { name: 'route:read:catalogue', description: 'Accéder à la page catalogue' },
      { name: 'route:read:documentation', description: 'Accéder à la documentation' },
      { name: 'route:read:support-service', description: 'Accéder aux outils de support' },

      // Routes d'administration
      { name: 'route:admin:users', description: 'Accéder à la gestion utilisateurs' },
      { name: 'route:admin:system', description: 'Accéder à l\'administration système' },
      { name: 'route:admin:roles', description: 'Accéder à la gestion des rôles' },

      // 🔌 PERMISSIONS API - Structure hiérarchique
      { name: 'api', description: 'Accès à toutes les API' },

      // API par domaine (permissions courtes = plus de droits)
      { name: 'api:user', description: 'Toutes opérations utilisateur' },
      { name: 'api:role', description: 'Toutes opérations rôles' },
      { name: 'api:annuaire', description: 'Toutes opérations annuaire' },
      { name: 'api:installation', description: 'Toutes opérations installation' },
      { name: 'api:catalogue', description: 'Toutes opérations catalogue' },
      { name: 'api:documentation', description: 'Toutes opérations documentation' },
      { name: 'api:support', description: 'Toutes opérations support' },
      { name: 'api:system', description: 'Toutes opérations système' },

      // API par type d'action (avec wildcard interne pour éviter duplication)
      { name: 'api:*:read', description: 'Lecture sur toutes les API' },
      { name: 'api:*:write', description: 'Écriture sur toutes les API' },
      { name: 'api:*:delete', description: 'Suppression sur toutes les API' },

      // API spécifiques pour contrôle fin
      { name: 'api:user:read', description: 'Consulter les utilisateurs' },
      { name: 'api:user:write', description: 'Modifier les utilisateurs' },
      { name: 'api:user:delete', description: 'Supprimer les utilisateurs' },
      { name: 'api:user:read:self', description: 'Consulter son propre profil' },
      { name: 'api:user:write:self', description: 'Modifier son propre profil' },

      { name: 'api:annuaire:read', description: 'Consulter l\'annuaire' },
      { name: 'api:annuaire:write', description: 'Modifier l\'annuaire' },
      { name: 'api:annuaire:delete', description: 'Supprimer des entrées annuaire' },

      { name: 'api:installation:read', description: 'Consulter les installations' },
      { name: 'api:installation:write', description: 'Modifier les installations' },
      { name: 'api:installation:delete', description: 'Supprimer des installations' },

      { name: 'api:catalogue:read', description: 'Consulter le catalogue' },
      { name: 'api:catalogue:write', description: 'Modifier le catalogue' },
      { name: 'api:catalogue:publish', description: 'Publier dans le catalogue' },

      { name: 'api:documentation:read', description: 'Consulter la documentation' },
      { name: 'api:documentation:write', description: 'Modifier la documentation' },

      { name: 'api:support:read', description: 'Consulter les tickets support' },
      { name: 'api:support:write', description: 'Créer/modifier des tickets' },

      { name: 'api:system:config', description: 'Configuration système' },
      { name: 'api:system:logs', description: 'Accès aux logs système' },
      { name: 'api:system:backup', description: 'Gestion des sauvegardes' },
    ];
  }

  /**
   * Mapping intelligent de l'ancien système vers le nouveau
   * Utilise la stratégie "permission la plus courte possible"
   */
  private mapOldToOptimizedPermissions(oldStructure: OldRoleStructure): { [roleName: string]: string[] } {
    const mapping: { [roleName: string]: string[] } = {};

    for (const [roleName, perms] of Object.entries(oldStructure)) {
      const permissions: string[] = [];

      // 🔍 Analyser les consultations
      const consultationRoutes = [];
      if (perms.consultation?.annuaire) {
        consultationRoutes.push('annuaire');
        permissions.push('route:read:annuaire');
        permissions.push('api:annuaire:read');
      }
      if (perms.consultation?.installation) {
        consultationRoutes.push('installation');
        permissions.push('route:read:installation');
        permissions.push('api:installation:read');
      }
      if (perms.consultation?.referentiel_technique) {
        consultationRoutes.push('referentiel-technique');
        permissions.push('route:read:referentiel-technique');
        permissions.push('api:referentiel:read');
      }

      // Si accès à toutes les consultations → optimiser avec permission courte
      if (consultationRoutes.length >= 3) {
        // Remplacer par permissions plus courtes
        permissions.length = 0;
        permissions.push('route:read');
        permissions.push('api:*:read');
      }

      // 📋 Catalogue
      if (perms.catalogue) {
        permissions.push('route:read:catalogue');
        permissions.push('api:catalogue:read');
      }

      // 📚 Documentation
      if (perms.documentation) {
        permissions.push('route:read:documentation');
        permissions.push('api:documentation:read');
      }

      // 🔧 Support
      if (perms.outils?.support_service) {
        permissions.push('route:read:support-service');
        permissions.push('api:support:read');
      }

      // 🛠️ Administration
      if (perms.administration) {
        permissions.push('route:admin');
        permissions.push('api:user');
        permissions.push('api:role');
        permissions.push('api:system');
      }

      // 🎯 Permissions étendues selon le niveau du rôle
      switch (roleName) {
        case 'MOA':
          // MOA = consultation pure
          break;

        case 'SSE':
        case 'SSESANSMDP':
          // SSE = sécurité → logs + modifications installations
          if (perms.consultation?.installation) {
            permissions.push('api:installation:write');
          }
          permissions.push('api:system:logs');
          break;

        case 'CHEF DE PROJET':
          // Chef de projet = vue d'ensemble + modifications limitées
          if (perms.consultation?.installation) {
            permissions.push('api:installation:write');
          }
          permissions.push('api:user:read:self');
          break;

        case 'CCN MULTIMEDIA':
          // CCN = technicien avancé
          if (perms.catalogue) {
            permissions.push('api:catalogue'); // Permission courte = tous droits catalogue
          }
          if (perms.outils?.support_service) {
            permissions.push('api:support'); // Permission courte = tous droits support
          }
          if (perms.documentation) {
            permissions.push('api:documentation:write');
          }
          break;

        case 'ADMINISTRATEUR':
          // Admin = super permissions
          permissions.length = 0;
          permissions.push('route');
          permissions.push('api');
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
        const apiPerms = permissionNames.filter(p => p.startsWith('api:'));

        console.log(`  ✅ ${roleName} (${newPermissions.length} permissions):`);
        if (routePerms.length > 0) {
          console.log(`     🚪 Routes: ${routePerms.join(', ')}`);
        }
        if (apiPerms.length > 0) {
          console.log(`     🔌 APIs: ${apiPerms.join(', ')}`);
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
   * Affichage du résumé final
   */
  private async displaySummary(): Promise<void> {
    console.log('\n=== RÉSUMÉ DE LA MIGRATION ===');

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

      const apiPermissions = role.permissions
        .filter((perm: Permission) => perm.name.startsWith('api:'))
        .map((perm: Permission) => perm.name)
        .sort();

      if (routePermissions.length > 0) {
        console.log(`   🚪 Routes (${routePermissions.length}):`);
        routePermissions.forEach((perm: string) => console.log(`      - ${perm}`));
      }

      if (apiPermissions.length > 0) {
        console.log(`   🔌 APIs (${apiPermissions.length}):`);
        apiPermissions.forEach((perm: string) => console.log(`      - ${perm}`));
      }

      if (routePermissions.length === 0 && apiPermissions.length === 0) {
        console.log('   - Aucune permission route/api');
      }
    }
  }

  /**
   * Migration depuis un fichier JSON
   */
  async migrateFromFile(filePath: string): Promise<void> {
    console.log(`📖 Reading role structure from: ${filePath}`);

    if (!fs.existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }

    const fileContent = fs.readFileSync(filePath, 'utf8');
    const oldStructure: OldRoleStructure = JSON.parse(fileContent);

    await this.migrate(oldStructure);
  }
}

/**
 * Script principal d'exécution
 */
async function runMigration() {
  // Configuration TypeORM
  const dataSource = new DataSource({
    type: 'postgres',
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '5432'),
    username: process.env.DB_USERNAME || 'postgres',
    password: process.env.DB_PASSWORD || 'password',
    database: process.env.DB_DATABASE || 'testdb',
    entities: [Role, Permission, User],
    synchronize: false,
    logging: false,
  });

  await dataSource.initialize();
  console.log('✅ Database connection established');

  try {
    const migrator = new OptimizedPermissionMigrator(dataSource);

    // Chemin vers le fichier de données
    const dataFilePath = path.join(__dirname, '..', '..', 'data', 'legacy-roles.json');

    await migrator.migrateFromFile(dataFilePath);

  } finally {
    await dataSource.destroy();
    console.log('🔌 Database connection closed');
  }
}

// Exécution si lancé directement
if (require.main === module) {
  runMigration()
    .then(() => {
      console.log('\n✨ Migration terminée avec succès !');
      process.exit(0);
    })
    .catch((error) => {
      console.error('\n💥 Erreur lors de la migration :', error);
      process.exit(1);
    });
}

export { OptimizedPermissionMigrator };
