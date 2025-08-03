#!/bin/bash

# Script helper pour exécuter les tests de permissions dans Docker
# Usage: ./scripts/test-permissions.sh

echo "🧪 Testing permission logic in Docker environment..."
echo "=========================================="

# Vérifier que le conteneur backend tourne
if ! docker ps | grep -q "node_server"; then
    echo "❌ Le conteneur node_server n'est pas en cours d'exécution"
    echo "   Lancez d'abord: docker-compose up -d"
    exit 1
fi

echo "✅ Conteneur backend détecté"
echo "🚀 Exécution du test des permissions..."
echo ""

# Exécuter le test dans le conteneur
docker exec -it node_server bash -c "cd ${PROJECT_BACK_DIR:-/src/app/back} && pnpm run test:permissions"

echo ""
echo "✅ Test terminé!"
