ARG IMAGE_TAG=latest
FROM --platform=$BUILDPLATFORM ghcr.io/zama-ai/kms-service:${IMAGE_TAG}

# FIXME: do we still want a "dev" image with pregenerated keys at all?
#RUN mkdir -p /app/kms/core/service/keys
#RUN /app/kms/core/service/bin/kms-gen-keys centralized --overwrite --write-privkey

CMD ["kms-server", "centralized"]
