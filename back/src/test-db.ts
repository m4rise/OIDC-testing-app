import 'reflect-metadata';
import dotenv from 'dotenv';
import { AppDataSource } from './data-source';

dotenv.config();

async function testConnection() {
  try {
    console.log('🔄 Testing database connection...');
    console.log('Connection config:', {
      host: process.env.PG_HOST,
      port: process.env.PG_PORT,
      database: process.env.POSTGRES_DB,
      username: process.env.POSTGRES_USER,
      // Don't log password
    });

    await AppDataSource.initialize();
    console.log('✅ Database connection successful!');

    await AppDataSource.destroy();
    console.log('✅ Database connection closed.');

    process.exit(0);
  } catch (error) {
    console.error('❌ Database connection failed:', error);
    process.exit(1);
  }
}

testConnection();
