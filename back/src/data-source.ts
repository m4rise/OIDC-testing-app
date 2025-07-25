import 'reflect-metadata';
import { DataSource } from 'typeorm';
import dotenv from 'dotenv';
import { User } from './entities/User';
import { Session } from './entities/Session';
import { Role } from './entities/Role';
import { Permission } from './entities/Permission';
import { config } from './config/environment';

// Load environment variables
dotenv.config();

export const AppDataSource = new DataSource({
  type: 'postgres',
  host: config.database.host,
  port: config.database.port,
  username: config.database.username,
  password: config.database.password,
  database: config.database.database,
  synchronize: config.isDevelopment,
  logging: config.isDevelopment,
  entities: [User, Session, Role, Permission], // Added new entities
  migrations: ['src/migrations/**/*.ts'],
  subscribers: ['src/subscribers/**/*.ts'],
});
