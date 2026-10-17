#!/bin/sh
# Assemble the DSN from a secret file so no password sits in the environment of
# the image or in `docker inspect` output (R-OPS-05).
set -eu

if [ -z "${ABB_DB_DSN:-}" ]; then
  if [ -z "${ABB_DB_PASSWORD_FILE:-}" ] || [ ! -r "${ABB_DB_PASSWORD_FILE}" ]; then
    echo "ABB_DB_DSN or ABB_DB_PASSWORD_FILE must be provided" >&2
    exit 1
  fi
  # Read, use, do not echo.
  ABB_DB_PASSWORD="$(cat "${ABB_DB_PASSWORD_FILE}")"
  export ABB_DB_DSN="postgresql://${ABB_DB_USER}:${ABB_DB_PASSWORD}@${ABB_DB_HOST}:5432/${ABB_DB_NAME}"
  unset ABB_DB_PASSWORD
fi

exec uvicorn services.api.main:build --factory --host 0.0.0.0 --port 8000
