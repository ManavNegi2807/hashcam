#!/bin/sh
# Read the ingestion public key from its secret file, then exec the signer.
# Nothing here echoes a key, and the signer's own key is never read by this
# script: only the signer process opens it.
set -eu

if [ -z "${ABB_SIGNER_INGESTION_PUBKEY:-}" ]; then
  if [ -z "${ABB_SIGNER_INGESTION_PUBKEY_FILE:-}" ] || [ ! -r "${ABB_SIGNER_INGESTION_PUBKEY_FILE}" ]; then
    echo "ABB_SIGNER_INGESTION_PUBKEY or ABB_SIGNER_INGESTION_PUBKEY_FILE must be provided" >&2
    exit 1
  fi
  ABB_SIGNER_INGESTION_PUBKEY="$(cat "${ABB_SIGNER_INGESTION_PUBKEY_FILE}")"
  export ABB_SIGNER_INGESTION_PUBKEY
fi

exec /usr/local/bin/abb-signer
