ARG IMAGE_NAME=kms-service
ARG IMAGE_TAG=latest

FROM --platform=$BUILDPLATFORM ${IMAGE_NAME}:${IMAGE_TAG}

ARG IMAGE_NAME

COPY --from=eif enclave.eif /app/kms/core/service/enclave.eif

# This is not going to be used in practice because Helm charts specify their own
# commands when starting containers.
CMD ["kms-server", "centralized"]
