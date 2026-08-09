# rust:alpine targets musl natively, so the binary is static and the
# runtime image can be scratch: no base OS, nothing to patch, nothing to
# exploit. The built image is around 3 MB.
FROM rust:alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
# The version the binary identifies as (shown in the admin UI). Set from
# the git tag by the images workflow; cargo tracks the env dependency,
# so a changed version re-links.
ARG POSTBUD_VERSION
ENV POSTBUD_VERSION=${POSTBUD_VERSION}
RUN cargo build --release -p postbud-cli

FROM scratch
COPY --from=builder /src/target/release/postbud /postbud
ENTRYPOINT ["/postbud"]
