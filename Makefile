
help:
	@printf "Help commands for demo app:\n"

run-containers:
	docker-compose -f etc/docker-compose/keycloak-postgres.yml up -d

kill-containers:
	docker-compose -f etc/docker-compose/keycloak-postgres.yml down