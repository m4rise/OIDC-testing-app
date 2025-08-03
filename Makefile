# Makefile pour simplifier les commandes Docker
.PHONY: up down test-permissions migrate-permissions logs

# Démarrer l'environnement
up:
	docker-compose up -d

# Arrêter l'environnement
down:
	docker-compose down

# Tester la logique des permissions
test-permissions:
	@echo "🧪 Testing permission logic..."
	docker exec -it node_server pnpm run test:permissions

# Exécuter la migration des permissions
migrate-permissions:
	@echo "🚀 Running permission migration..."
	docker exec -it node_server pnpm run script:migrate-permissions

# Voir les logs du backend
logs:
	docker-compose logs -f node_server

# Entrer dans le conteneur backend
shell:
	docker exec -it node_server bash

# Tout en un: démarrer et tester
dev: up test-permissions
