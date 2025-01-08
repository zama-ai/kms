ARG IMAGE_NAME=kms-service
ARG IMAGE_TAG=latest

# Build nitro-cli (used to start enclaves only)
FROM --platform=$BUILDPLATFORM rust:1.81-slim-bookworm AS nitro-cli

RUN --mount=type=cache,sharing=locked,target=/var/cache/apt apt update && \
    apt install -y make git libssl-dev pkg-config

WORKDIR /build
RUN git clone https://github.com/aws/aws-nitro-enclaves-cli --branch v1.3.3 --single-branch

WORKDIR aws-nitro-enclaves-cli
RUN make nitro-cli-native

# Build final image

FROM --platform=$BUILDPLATFORM ${IMAGE_NAME}:${IMAGE_TAG}

COPY --from=nitro-cli /build/aws-nitro-enclaves-cli/build/nitro_cli/release/nitro-cli /app/kms/core/service/bin

RUN mkdir -p /var/log/nitro_enclaves
RUN mkdir -p /run/nitro_enclaves

COPY --from=eif enclave.eif /app/kms/core/service/enclave.eif


# Change user to limit root access
RUN groupadd -g 10002 kms && \
    useradd -m -u 10003 -g kms kms
# pre-create mount points for rights
RUN mkdir -p /app/kms/core/service/certs /app/kms/core/service/config
RUN chown -R kms:kms /app/kms
USER kms

# This is not going to be used in practice because Helm charts specify their own
# commands when starting containers.
CMD ["kms-server", "centralized"]
