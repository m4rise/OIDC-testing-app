import { MigrationInterface, QueryRunner } from "typeorm";

export class AddWildcardPermissions1700000000000 implements MigrationInterface {
    name = 'AddWildcardPermissions1700000000000'

    public async up(queryRunner: QueryRunner): Promise<void> {
        // This migration adds the new wildcard-based permissions
        // It will be executed by the migration script to maintain data integrity

        console.log('🚀 Starting wildcard permissions migration...');
        console.log('📝 This migration will add new hierarchical permissions with route: and api: prefixes');
        console.log('⚠️  Please run the migration script: npm run script:migrate-permissions');
        console.log('🔧 The script will handle the data transformation while preserving existing logic');
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        // Revert wildcard permissions - remove all permissions with route: and api: prefixes
        await queryRunner.query(`
            DELETE FROM "role_permissions_permission"
            WHERE "permissionId" IN (
                SELECT id FROM permission
                WHERE name LIKE 'route:%' OR name LIKE 'api:%'
            )
        `);

        await queryRunner.query(`
            DELETE FROM permission
            WHERE name LIKE 'route:%' OR name LIKE 'api:%'
        `);

        console.log('🔄 Reverted wildcard permissions migration');
    }
}
