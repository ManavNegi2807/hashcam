# The one FastAPI service, with the `abb` binary it needs for canonicalization.
#
# Status: IMPLEMENTED, NOT TESTED. Never built: no Docker daemon was available
# when Step 3 was written.
#
# Two stages so the Rust toolchain does not ship in the runtime image, and the
# runtime runs as a non-root user with no build tools (R-OPS-02).

FROM rust:1.90-alpine AS core
RUN apk add --no-cache musl-dev
WORKDIR /src
# Copy only what the workspace needs, so a change to the service does not
# rebuild the core.
COPY core/ ./core/
RUN cd core && cargo build --release -p abb-cli

FROM python:3.13-alpine AS runtime
# A fixed uid, matching the `user:` in docker-compose.yml.
RUN adduser -D -u 10001 abb
WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY --from=core /src/core/target/release/abb /usr/local/bin/abb
COPY services/ ./services/
COPY deploy/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

USER abb
EXPOSE 8000
# The signer key volume is never mounted here (R-OPS-03): this image has no
# business holding one, and the service never signs anything.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
