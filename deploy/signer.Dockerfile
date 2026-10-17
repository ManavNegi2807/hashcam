# The separate signer: one small binary, its own key volume, no Python, no
# database client, nothing else.
#
# Status: IMPLEMENTED, NOT TESTED. Never built: no Docker daemon was available
# when Step 4 was written.

FROM rust:1.90-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY core/ ./core/
COPY signer/ ./signer/
RUN cd core && cargo build --release -p abb-signer

# `scratch` would be ideal, but the signer needs a shell-free entrypoint plus a
# CA-free minimal base; alpine keeps it small and gives a healthcheck binary.
FROM alpine:3.21 AS runtime
RUN adduser -D -u 10002 signer
COPY --from=build /src/core/target/release/abb-signer /usr/local/bin/abb-signer
COPY deploy/signer-entrypoint.sh /usr/local/bin/signer-entrypoint.sh
RUN chmod +x /usr/local/bin/signer-entrypoint.sh
USER signer
EXPOSE 8081
# No database client is installed, so even a mistake in configuration cannot
# give this container database access (R-SIG-02).
ENTRYPOINT ["/usr/local/bin/signer-entrypoint.sh"]
