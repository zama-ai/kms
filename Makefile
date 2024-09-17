build-compose-threshold:
	docker compose -vvv -f docker-compose-kms-base.yml -f docker-compose-kms-threshold.yml build

start-compose-threshold:
	docker compose -vvv -f docker-compose-kms-base.yml -f docker-compose-kms-threshold.yml up -d --wait

start-compose-threshold-ghcr:
	docker compose -vvv -f docker-compose-kms-base.yml -f docker-compose-kms-threshold.yml -f docker-compose-kms-threshold-ghcr.yml up -d --wait

stop-compose-threshold:
	docker compose -vvv -f docker-compose-kms-base.yml -f docker-compose-kms-threshold.yml down --volumes --remove-orphans

start-compose-threshold-ghcr:
	docker compose -vvv -f docker-compose-kms-base.yml -f docker-compose-kms-threshold.yml -f docker-compose-kms-threshold-ghcr.yml up -d --wait

