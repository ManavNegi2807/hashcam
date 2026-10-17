//! The signer's narrow HTTP API (`DATABASE_AND_API_CONTRACTS.md` B4).
//!
//! Three routes and nothing else (`R-SIG-02`):
//!
//! * `POST /sign` — a signing request (`PROTOCOL.md` 11.1);
//! * `GET /state/{stream_id}` — the last checkpoint, for idempotent re-delivery;
//! * `GET /health` — liveness, with no configuration in the answer.
//!
//! It is reachable only from the ingestion service over the signer network, and
//! every request must carry a `caller_attestation` signed by the ingestion key
//! (`D-20`). There is no auth token to leak and no database connection to make.
//!
//! Configuration comes from the environment. A missing value is an error, never
//! a default: a signer that invents its own key path is a signer nobody can
//! reason about.

#![forbid(unsafe_code)]

use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

use abb_jcs::{hex_decode, Limits, Value};
use abb_signer::{Config, Signer, SignerError};
use tiny_http::{Header, Request, Response, Server};

const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            // Startup failures go to stderr. They never include key material.
            eprintln!("abb-signer: {message}");
            ExitCode::FAILURE
        }
    }
}

fn env_var(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("{name} must be set"))
}

fn run() -> Result<(), String> {
    let state_dir = PathBuf::from(env_var("ABB_SIGNER_STATE_DIR")?);
    let key_path = PathBuf::from(env_var("ABB_SIGNER_KEY")?);
    let ingestion_hex = env_var("ABB_SIGNER_INGESTION_PUBKEY")?;
    let addr = std::env::var("ABB_SIGNER_ADDR").unwrap_or_else(|_| "127.0.0.1:8081".to_owned());
    let rate_limit: u32 = std::env::var("ABB_SIGNER_RATE_LIMIT")
        .unwrap_or_else(|_| "50".to_owned())
        .parse()
        .map_err(|_| "ABB_SIGNER_RATE_LIMIT must be a whole number".to_owned())?;

    let ingestion_public_key: [u8; 32] = hex_decode(&ingestion_hex)
        .map_err(|_| "ABB_SIGNER_INGESTION_PUBKEY must be 64 lowercase hex characters".to_owned())?
        .try_into()
        .map_err(|_| "ABB_SIGNER_INGESTION_PUBKEY must be 32 bytes".to_owned())?;

    let mut signer = Signer::open(Config {
        state_dir,
        key_path,
        ingestion_public_key,
        rate_limit_per_second: rate_limit,
    })
    .map_err(|e| match e {
        SignerError::StateCorrupt => {
            "state log is corrupt: refusing to sign. A recovery ceremony is required \
             (see signer/README.md); the signer will not reset itself"
                .to_owned()
        }
        SignerError::StateLocked => {
            "another signer process is already using this state directory. Two signers on \
             one state log could sign conflicting histories, so this one will not start"
                .to_owned()
        }
        other => format!("cannot start: {other}"),
    })?;

    let server = Server::http(&addr).map_err(|e| format!("cannot listen on {addr}: {e}"))?;
    // Says which key is in use, never the key itself.
    println!("abb-signer listening on {addr} as {}", signer.key_id());

    for mut request in server.incoming_requests() {
        let response = handle(&mut signer, &mut request);
        let _ = request.respond(response);
    }
    Ok(())
}

fn json_header() -> Header {
    // Unwrap-free: this header is a compile-time constant pair.
    Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
        .unwrap_or_else(|_| unreachable!("a constant header always parses"))
}

fn json(status: u16, value: &Value) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = abb_jcs::to_canonical_with(value, &Limits::relaxed())
        .unwrap_or_else(|_| "{\"code\":\"STATE_UNAVAILABLE\"}".to_owned());
    Response::from_data(body.into_bytes())
        .with_status_code(status)
        .with_header(json_header())
}

fn error_response(error: &SignerError) -> Response<std::io::Cursor<Vec<u8>>> {
    json(
        error.http_status(),
        &Value::Object(vec![
            ("code".to_owned(), Value::Str(error.as_str().to_owned())),
            ("detail".to_owned(), Value::Str(error.detail())),
        ]),
    )
}

fn handle(signer: &mut Signer, request: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
    let method = request.method().as_str().to_owned();
    let url = request.url().to_owned();

    match (method.as_str(), url.as_str()) {
        ("GET", "/health") => json(
            200,
            &Value::Object(vec![
                ("status".to_owned(), Value::Str("ok".to_owned())),
                ("key_id".to_owned(), Value::Str(signer.key_id().to_owned())),
                (
                    "protocol_version".to_owned(),
                    Value::Str("abb/1".to_owned()),
                ),
            ]),
        ),
        ("POST", "/sign") => {
            let mut body = Vec::new();
            let limit = request.body_length().unwrap_or(0);
            if limit > MAX_BODY_BYTES {
                return error_response(&SignerError::BadAppendEvidence(
                    "request body over the signer's size limit".to_owned(),
                ));
            }
            if request
                .as_reader()
                .take(MAX_BODY_BYTES as u64)
                .read_to_end(&mut body)
                .is_err()
            {
                return error_response(&SignerError::BadAppendEvidence(
                    "request body could not be read".to_owned(),
                ));
            }
            match signer.sign_json(&body) {
                Ok(checkpoint) => {
                    // `payload_b64` carries the exact bytes the signature
                    // covers, so the caller stores those rather than
                    // re-serializing the payload object and hoping (R-PRO-04).
                    let payload = checkpoint.payload.canonical_bytes().unwrap_or_default();
                    let hash = checkpoint.payload.checkpoint_hash_hex().unwrap_or_default();
                    json(
                        200,
                        &Value::Object(vec![
                            ("checkpoint".to_owned(), checkpoint.to_value()),
                            (
                                "payload_b64".to_owned(),
                                Value::Str(abb_jcs::b64::encode(&payload)),
                            ),
                            ("checkpoint_hash".to_owned(), Value::Str(hash)),
                        ]),
                    )
                }
                Err(error) => error_response(&error),
            }
        }
        ("GET", path) if path.starts_with("/state/") => {
            let stream_id = path.trim_start_matches("/state/");
            match signer.state(stream_id) {
                None => error_response(&SignerError::UnknownStream),
                Some(state) => json(
                    200,
                    &Value::Object(vec![
                        ("stream_id".to_owned(), Value::Str(stream_id.to_owned())),
                        ("tree_size".to_owned(), Value::Int(state.tree_size)),
                        ("root_hash".to_owned(), Value::Str(state.root_hash.clone())),
                        (
                            "checkpoint_hash".to_owned(),
                            Value::Str(state.checkpoint_hash.clone()),
                        ),
                        ("checkpoint".to_owned(), state.checkpoint.to_value()),
                    ]),
                ),
            }
        }
        _ => json(
            404,
            &Value::Object(vec![
                ("code".to_owned(), Value::Str("NOT_FOUND".to_owned())),
                (
                    "detail".to_owned(),
                    Value::Str(
                        "the signer serves /sign, /state/{stream_id} and /health".to_owned(),
                    ),
                ),
            ]),
        ),
    }
}
