# Permission System Migration

## Overview

Cette migration transforme votre ancien système de permissions vers un nouveau système basé sur des wildcards hiérarchiques, tout en préservant votre logique `matchesPermission` existante.

## Structure des nouvelles permissions

### Route Permissions (Frontend Guards)
- `route` - Accès à toutes les routes
- `route:read` - Accès à toutes les pages de consultation
- `route:admin` - Accès à toutes les pages d'administration
- `route:read:annuaire` - Page annuaire spécifique
- `route:read:installation` - Page installations spécifique
- etc.

### API Permissions (Backend Endpoints)
- `api` - Accès à toutes les APIs
- `api:read` - Accès en lecture à toutes les APIs
- `api:write` - Accès en écriture à toutes les APIs
- `api:admin` - Accès aux APIs d'administration
- `api:read:users` - API utilisateurs en lecture
- etc.

## Logique hiérarchique préservée

Votre logique `matchesPermission` existante est complètement préservée :
- Une permission courte couvre les permissions plus longues
- `route:read` donne accès à `route:read:annuaire`, `route:read:installation`, etc.
- `api` donne accès à toutes les APIs

## Migration Steps

### 1. Préparer vos anciennes données

Éditez le fichier `src/scripts/oldPermissionsData.json` avec votre structure actuelle :

```json
{
  "admin": {
    "consultation": {
      "annuaire": true,
      "installation": true,
      "referentiel_technique": true
    },
    "outils": {
      "support_service": true
    },
    "catalogue": true,
    "administration": true,
    "documentation": true
  },
  "user": {
    "consultation": {
      "annuaire": true
    },
    "catalogue": true,
    "documentation": true
  }
}
```

### 2. Exécuter la migration

```bash
# Lancer la migration des permissions
npm run script:migrate-permissions

# Ou directement avec ts-node
npx ts-node src/scripts/runPermissionMigration.ts
```

### 3. Vérifier les résultats

La migration va :
- ✅ Créer toutes les nouvelles permissions hiérarchiques
- ✅ Mapper vos anciens rôles vers les nouvelles permissions
- ✅ Préserver votre logique `matchesPermission` existante
- ✅ Afficher un résumé des opérations effectuées

### 4. Mise à jour du code

#### Frontend (Angular Guards)
```typescript
// Ancien
canActivate() {
  return this.authService.hasPermission('consultation.annuaire');
}

// Nouveau
canActivate() {
  return this.authService.hasPermission('route:read:annuaire');
}
```

#### Backend (API Endpoints)
```typescript
// Ancien
@hasPermission('administration')
async updateUser() { ... }

// Nouveau
@hasPermission('api:write:users')
async updateUser() { ... }
```

## Mapping automatique

La migration mappe automatiquement :

| Ancienne permission | Nouvelles permissions |
|-------------------|---------------------|
| `consultation.annuaire` | `route:read:annuaire` + `api:read:users` |
| `consultation.installation` | `route:read:installation` + `api:read:installations` |
| `administration` | `route:admin` + `api:admin` |
| `catalogue` | `route:read:catalogue` + `api:read:catalogue` |

## Rollback

Si besoin de revenir en arrière :

```bash
# Utiliser la migration TypeORM pour rollback
npm run migration:revert
```

## Testing

Après migration, votre logique `matchesPermission` fonctionne exactement comme avant :

```typescript
// Ces appels continuent de fonctionner
matchesPermission('route:read', 'route:read:annuaire') // true
matchesPermission('api', 'api:read:users') // true
matchesPermission('route:admin', 'route:read:annuaire') // false
```

## Support

En cas de problème :
1. Vérifiez les logs de la migration
2. Testez vos permissions avec les nouveaux noms
3. Utilisez le rollback si nécessaire
4. Consultez ce README pour les exemples de mapping
