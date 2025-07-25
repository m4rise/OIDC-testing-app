# RBAC Implementation Guide

## Overview
This project now uses Role-Based Access Control (RBAC) with permission-based authorization instead of simple role-based checks.

## Permission Format
Permissions follow the pattern: `[SCOPE]:[ENTITY]:[ACTION]:[CONTEXT]` with wildcard support.

Examples:
- `api:user:read:self` - Read own user data
- `api:user:read:*` - Read any user data
- `api:user:write:*` - Create/update any user
- `api:user:delete:*` - Delete any user
- `api:user:*` - All user operations
- `api:*` - All API operations
- `ui:delete-button` - Show delete buttons in UI
- `ui:*` - Show any UI elements
- `route:admin` - Access admin routes
- `route:*` - Access any route

## Wildcard Hierarchy
The `*` wildcard enables hierarchical permissions:
- `api:*` covers `api:user:read:self`, `api:user:write:*`, etc.
- `api:user:*` covers `api:user:read:self`, `api:user:write:*`, etc.
- `api:user:read:*` covers `api:user:read:self` but NOT `api:user:write:self`## Backend Usage

### Middleware
```typescript
import { requirePermission, requireRole } from '../middleware/rbac';

// Permission-based (recommended)
router.get('/users', requirePermission('api:user:read:*'), controller.getUsers);

// Role-based (when needed)
router.get('/stats', requireRole('admin'), controller.getStats);
```

### Controller
```typescript
// Session automatically includes user permissions
const sessionUser = getSessionUser(req);
const permissions = sessionUser.permissions; // ['api:user:read:*', ...]
const roles = sessionUser.roles; // ['admin', 'moderator']
```

## Frontend Usage

### Route Guards
```typescript
import { canReadUsers, canAccessAdmin } from './core/guards/permission.guard';

const routes = [
  { path: 'users', canActivate: [canReadUsers], ... },
  { path: 'admin', canActivate: [canAccessAdmin], ... }
];
```

### Components
```typescript
import { PermissionService } from './core/services/permission.service';

@Component({...})
export class UsersComponent {
  protected permissionService = inject(PermissionService);
}
```

### Templates
```html
<!-- Permission-based visibility -->
@if (permissionService.canEditUser()) {
  <button (click)="editUser()">Edit</button>
}

@if (permissionService.canDeleteUser()) {
  <button (click)="deleteUser()">Delete</button>
}
```

### Service Methods
```typescript
// Check permissions
authService.hasPermission('api:user:write:*')
authService.hasRole('admin')

// Convenience methods
permissionService.canEditUser()
permissionService.canDeleteUser()
permissionService.canShowElement('admin-tools')
```

## Migration from Legacy

### Removed
- ❌ Legacy role enums (`UserRole.ADMIN`, etc.)
- ❌ Simple role-based guards (`adminGuard`, `moderatorGuard`)
- ❌ Over-engineered auth-utils helper file

### Updated
- ✅ User model now has `roles: string[]` and `permissions: string[]`
- ✅ AuthService uses RBAC permission checking with wildcards
- ✅ Components use PermissionService for UI visibility
- ✅ Routes use permission-based guards

## Permission Wildcards
User permissions support hierarchical wildcard matching with `*` symbol:
- User has `api:*` → Can access `api:user:read:self`, `api:user:write:*`, etc.
- User has `api:user:*` → Can access `api:user:read:self`, `api:user:write:*`, etc.
- User has `api:user:read:*` → Can access `api:user:read:self` but NOT `api:user:write:self`
- User has `api:user` → Can access `api:user:read:self` (hierarchical without wildcards)
- Direct match: `api:user:read:self` matches exactly

**Algorithm**: Shorter permissions cover longer ones. Each part must match exactly or be `*`.

## Key Files
- **Backend**: `/middleware/rbac.ts` - Main RBAC middleware
- **Frontend**: `/core/services/permission.service.ts` - UI permission checks
- **Guards**: `/core/guards/permission.guard.ts` - Route protection
- **Models**: `/core/models/user.model.ts` - Updated user interface
