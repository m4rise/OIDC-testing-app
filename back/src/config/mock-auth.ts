import { UserRole } from '../entities/User';

export interface MockUser {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  role: UserRole;
  sub: string;
}

// Mock users for development (using UUID format for compatibility with database)
export const mockUsers: MockUser[] = [
  {
    id: '550e8400-e29b-41d4-a716-446655440001',
    email: 'admin@example.com',
    firstName: 'Admin',
    lastName: 'User',
    role: UserRole.ADMIN,
    sub: 'mock-admin-123'
  },
  {
    id: '550e8400-e29b-41d4-a716-446655440002',
    email: 'user@example.com',
    firstName: 'Regular',
    lastName: 'User',
    role: UserRole.USER,
    sub: 'mock-user-456'
  },
  {
    id: '550e8400-e29b-41d4-a716-446655440003',
    email: 'manager@example.com',
    firstName: 'Manager',
    lastName: 'User',
    role: UserRole.MODERATOR, // Fixed: should be MODERATOR, not USER
    sub: 'mock-manager-789'
  }
];

export const configureMockOIDC = () => {
  console.log('🎭 Configuring Mock OIDC endpoints for development');
  console.log('🎭 Mock OIDC endpoints will be available at /api/mock-oidc/*');
  console.log('🎭 The OpenIDConnect strategy will use openid-client to connect to these endpoints');
  // The actual mock OIDC endpoints are set up by MockOidcController
  // No separate passport strategy needed - OpenIDConnectStrategy handles everything
};
