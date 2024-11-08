ARG IMAGE_TAG=latest
FROM --platform=$BUILDPLATFORM ghcr.io/zama-ai/kms-service:${IMAGE_TAG}

#RUN /app/kms/core/service/bin/kms-gen-keys centralized --overwrite --write-privkey

CMD ["kms-server", "centralized"]
