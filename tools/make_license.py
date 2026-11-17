# ruff: noqa: E501
"""Make and check HashCam Pro licence keys. Runs on YOUR computer only; nothing here is ever deployed.

    python tools/make_license.py init                      # once: make the key pair
    python tools/make_license.py sign --name "Acme Ltd"    # per buyer: print one licence key
    python tools/make_license.py sign --name "Acme" --expires 2027-12-31
    python tools/make_license.py check KEY                 # does this key verify?

Enterprise companies (each isolated by its own key; the owner key only signs the company's certificate):
    python tools/make_license.py org-init --org-id acme --org-name "Acme Ltd"   # prints the company certificate
    python tools/make_license.py member --org-id acme --role boss --name Dana     # one unique access key per person
    python tools/make_license.py member --org-id acme --role member --name Sam --scopes triage,verify
    python tools/make_license.py revoke --org-id acme --member-id m-1a2b3c4d      # prints a signed revocation list

How it works: you keep a PRIVATE key (an Ed25519 key) outside the repository. The matching PUBLIC key is
written to `site/pro/pubkey.js`, which is deployed with the site. A licence key is a small signed note
(the buyer's name, plan, dates, an id); the site checks the signature in the browser with the public key.
No server is involved.

The private key is never printed, never logged, and this tool refuses to write it inside the repository.
Whoever holds it can make licences, so keep a backup somewhere safe (a password manager's file storage, an
encrypted drive). If you lose it, existing licences keep working but you cannot make new ones for this
public key; if it leaks, make a new pair with `init --force` and send buyers new keys.

Needs the `cryptography` package (`pip install cryptography`).
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import secrets
import sys
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

REPO = Path(__file__).resolve().parents[1]
PUBKEY_JS = REPO / "site" / "pro" / "pubkey.js"
DEFAULT_KEY_FILE = Path.home() / ".hashcam" / "license-private.pem"
PREFIX = "HCPRO1"
ORG_PREFIX = "HCORG1"
MEMBER_PREFIX = "HCMEM1"
REVOKE_PREFIX = "HCREV1"
ORG_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
MEMBER_ID_RE = re.compile(r"^[A-Za-z0-9-]{1,40}$")
ROLES = ("boss", "member")
BOSS_SCOPES = ("triage", "verify", "reproduce", "notes", "members", "policy", "approve", "insights")
MEMBER_SCOPES = ("triage", "verify", "reproduce", "notes")
DEFAULT_ORG_DIR = Path.home() / ".hashcam" / "orgs"
NAME_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,80}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def make_keypair() -> tuple[Ed25519PrivateKey, str]:
    """A fresh key pair: the private key and the public key as 64 hex characters."""
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return private, public.hex()


def sign_license(
    private: Ed25519PrivateKey,
    name: str,
    *,
    expires: str | None = None,
    issued: str | None = None,
    license_id: str | None = None,
    plan: str = "pro",
    org: str | None = None,
    seats: int | None = None,
) -> str:
    """One licence key: HCPRO1.<payload>.<signature>, both base64url. Checks its own inputs."""
    if plan not in ("pro", "enterprise"):
        raise ValueError("the plan must be pro or enterprise")
    if org is not None and not NAME_RE.match(org):
        raise ValueError("the organisation must be 1 to 80 characters with no control characters")
    if seats is not None and not 1 <= seats <= 10000:
        raise ValueError("seats must be between 1 and 10000")
    if not NAME_RE.match(name):
        raise ValueError("the name must be 1 to 80 characters with no control characters")
    if expires is not None and not DATE_RE.match(expires):
        raise ValueError("expires must look like 2027-12-31")
    if expires is not None:
        date.fromisoformat(expires)  # raises on a date that does not exist
    issued = issued or datetime.now(UTC).date().isoformat()
    date.fromisoformat(issued)
    payload = {
        "v": 1,
        "name": name,
        "plan": plan,
        "issued": issued,
        "expires": expires,
        "id": license_id or secrets.token_hex(4),
    }
    if org is not None:
        payload["org"] = org
    if seats is not None:
        payload["seats"] = seats
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return f"{PREFIX}.{b64u(raw)}.{b64u(private.sign(raw))}"


def check_license(token: str, public_hex: str) -> dict[str, Any]:
    """Verify a licence key with a public key. Raises ValueError with a plain reason."""
    parts = token.strip().split(".")
    if len(parts) != 3 or parts[0] != PREFIX:
        raise ValueError("not a HashCam Pro key")
    raw, sig = unb64u(parts[1]), unb64u(parts[2])
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(sig, raw)
    except Exception as error:
        raise ValueError("the signature does not match this site's public key") from error
    payload: dict[str, Any] = json.loads(raw)
    if payload.get("plan") not in ("pro", "enterprise"):
        raise ValueError("not a Pro licence")
    return payload


def load_private(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit(f"{path} is not an Ed25519 private key")
    return key


def public_hex_in_site() -> str | None:
    match = re.search(r'publicKeyHex:\s*"([0-9a-f]{64})"', PUBKEY_JS.read_text(encoding="utf-8"))
    return match.group(1) if match else None


def inside_repo(path: Path) -> bool:
    try:
        path.resolve().relative_to(REPO)
    except ValueError:
        return False
    return True


PUBKEY_TEMPLATE = """// GENERATED by tools/make_license.py init: do not edit. The PUBLIC key that checks Pro licence
// keys in the browser. (The private key that makes them lives on the owner's computer, never in
// this repository.)
window.HCProKey = {{ publicKeyHex: "{public}" }};
"""


def cmd_init(args: argparse.Namespace) -> int:
    key_file = Path(args.key_file).expanduser()
    if inside_repo(key_file):
        print("Refusing: the private key must be saved OUTSIDE the repository.", file=sys.stderr)
        return 2
    if key_file.exists() and not args.force:
        print(
            f"A private key already exists at {key_file}. Use --force to replace it.",
            file=sys.stderr,
        )
        return 2
    private, public_hex = make_keypair()
    key_file.parent.mkdir(parents=True, exist_ok=True)
    pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(pem)
    PUBKEY_JS.write_text(PUBKEY_TEMPLATE.format(public=public_hex), encoding="utf-8", newline="\n")
    print(f"Private key saved to {key_file}")
    print("Keep a backup of that file somewhere safe. Never share it and never commit it.")
    try:
        shown = PUBKEY_JS.relative_to(REPO)
    except ValueError:
        shown = PUBKEY_JS
    print(f"Public key written to {shown}: commit that file and deploy.")
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    key_file = Path(args.key_file).expanduser()
    if not key_file.exists():
        print(f"No private key at {key_file}. Run `init` first.", file=sys.stderr)
        return 2
    try:
        token = sign_license(
            load_private(key_file),
            args.name,
            expires=args.expires,
            plan=args.plan,
            org=args.org,
            seats=args.seats,
        )
    except ValueError as error:
        print(f"Cannot make the licence: {error}", file=sys.stderr)
        return 2
    public = public_hex_in_site()
    if public is None:
        print(
            "Warning: site/pro/pubkey.js has no public key yet, so the site cannot check this.",
            file=sys.stderr,
        )
    print(token)
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    public = public_hex_in_site()
    if public is None:
        print("site/pro/pubkey.js has no public key yet. Run `init` first.", file=sys.stderr)
        return 2
    try:
        payload = check_license(args.key, public)
    except (ValueError, json.JSONDecodeError) as error:
        print(f"Does not verify: {error}")
        return 1
    print(
        f"Verifies: {payload.get('name')} (plan {payload.get('plan')}, expires {payload.get('expires')})"
    )
    return 0


# ---------------------------------------------------------------- companies, members, revocation
# Chain: the OWNER key signs a company certificate (HCORG1: org_id, org_name, the company's public key). The
# COMPANY key (made by org-init, kept outside the repo) signs each person's access key (HCMEM1) and the company's
# revocation list (HCREV1). So handing out member keys never needs the owner private key.


def _signed(prefix: str, private: Ed25519PrivateKey, payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return f"{prefix}.{b64u(raw)}.{b64u(private.sign(raw))}"


def check_signed(prefix: str, token: str, public_hex: str) -> dict[str, Any]:
    """Verify one HCORG1/HCMEM1/HCREV1 token with a public key. Raises ValueError with a plain reason."""
    parts = token.strip().split(".")
    if len(parts) != 3 or parts[0] != prefix:
        raise ValueError(f"not a {prefix} token")
    raw, sig = unb64u(parts[1]), unb64u(parts[2])
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(sig, raw)
    except Exception as error:
        raise ValueError("the signature does not match") from error
    payload: dict[str, Any] = json.loads(raw)
    return payload


def _day(value: str | None, label: str) -> None:
    if value is not None:
        if not DATE_RE.match(value):
            raise ValueError(f"{label} must look like 2027-12-31")
        date.fromisoformat(value)


def sign_org_cert(
    owner: Ed25519PrivateKey,
    org_id: str,
    org_name: str,
    org_pubkey: str,
    *,
    expires: str | None = None,
    issued: str | None = None,
) -> str:
    """The company certificate: HCORG1.<payload>.<signature>, signed by the owner key."""
    if not ORG_ID_RE.match(org_id):
        raise ValueError("org id: 1 to 40 characters, lower-case letters, digits and dashes")
    if not NAME_RE.match(org_name):
        raise ValueError("org name must be 1 to 80 characters with no control characters")
    if not re.fullmatch(r"[0-9a-f]{64}", org_pubkey):
        raise ValueError("the company public key must be 64 hex characters")
    _day(expires, "expires")
    issued = issued or datetime.now(UTC).date().isoformat()
    _day(issued, "issued")
    payload = {
        "v": 1,
        "org_id": org_id,
        "org_name": org_name,
        "org_pubkey": org_pubkey,
        "issued": issued,
        "expires": expires,
    }
    return _signed(ORG_PREFIX, owner, payload)


def sign_member(
    org_key: Ed25519PrivateKey,
    org_id: str,
    name: str,
    role: str,
    *,
    scopes: list[str] | None = None,
    expires_at: str | None = None,
    issued: str | None = None,
    member_id: str | None = None,
) -> str:
    """One person's access key: HCMEM1.<payload>.<signature>, signed by the COMPANY key."""
    if not ORG_ID_RE.match(org_id):
        raise ValueError("bad org id")
    if role not in ROLES:
        raise ValueError("the role must be boss or member")
    if not NAME_RE.match(name):
        raise ValueError("the name must be 1 to 80 characters with no control characters")
    allowed = BOSS_SCOPES if role == "boss" else MEMBER_SCOPES
    chosen = list(scopes) if scopes else list(allowed)
    if any(s not in allowed for s in chosen) or len(set(chosen)) != len(chosen):
        raise ValueError(f"scopes for a {role} can only be: {', '.join(allowed)}")
    member_id = member_id or f"m-{secrets.token_hex(4)}"
    if not MEMBER_ID_RE.match(member_id):
        raise ValueError("bad member id")
    _day(expires_at, "expires")
    issued = issued or datetime.now(UTC).date().isoformat()
    _day(issued, "issued")
    payload = {
        "v": 1,
        "org_id": org_id,
        "member_id": member_id,
        "name": name,
        "role": role,
        "scopes": chosen,
        "issued": issued,
        "expires_at": expires_at,
    }
    return _signed(MEMBER_PREFIX, org_key, payload)


def sign_revocations(
    org_key: Ed25519PrivateKey, org_id: str, revoked: list[str], *, issued: str | None = None
) -> str:
    """The company's revocation list: HCREV1.<payload>.<signature>. Revoking is NOT ENFORCED by a server."""
    if not ORG_ID_RE.match(org_id) or not all(MEMBER_ID_RE.match(m) for m in revoked):
        raise ValueError("bad org id or member id")
    issued = issued or datetime.now(UTC).date().isoformat()
    _day(issued, "issued")
    payload = {"v": 1, "org_id": org_id, "revoked": sorted(set(revoked)), "issued": issued}
    return _signed(REVOKE_PREFIX, org_key, payload)


def _org_key_path(args: argparse.Namespace) -> Path:
    return Path(args.org_dir).expanduser() / f"{args.org_id}-private.pem"


def _save_private(path: Path, private: Ed25519PrivateKey) -> None:
    pem = private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(pem)


def cmd_org_init(args: argparse.Namespace) -> int:
    owner_file = Path(args.key_file).expanduser()
    org_file = _org_key_path(args)
    if inside_repo(org_file):
        print(
            "Refusing: the company private key must be saved OUTSIDE the repository.",
            file=sys.stderr,
        )
        return 2
    if not owner_file.exists():
        print(f"No owner private key at {owner_file}. Run `init` first.", file=sys.stderr)
        return 2
    if org_file.exists() and not args.force:
        print(
            f"A company key already exists at {org_file}. Use --force to replace it.",
            file=sys.stderr,
        )
        return 2
    org_private, org_public = make_keypair()
    try:
        cert = sign_org_cert(
            load_private(owner_file), args.org_id, args.org_name, org_public, expires=args.expires
        )
    except ValueError as error:
        print(f"Cannot make the certificate: {error}", file=sys.stderr)
        return 2
    _save_private(org_file, org_private)
    print(
        f"Company private key saved to {org_file} (for this company's admin only; never commit it).",
        file=sys.stderr,
    )
    print(cert)
    return 0


def cmd_member(args: argparse.Namespace) -> int:
    org_file = _org_key_path(args)
    if not org_file.exists():
        print(f"No company key at {org_file}. Run `org-init` first.", file=sys.stderr)
        return 2
    scopes = [s.strip() for s in args.scopes.split(",") if s.strip()] if args.scopes else None
    try:
        token = sign_member(
            load_private(org_file),
            args.org_id,
            args.name,
            args.role,
            scopes=scopes,
            expires_at=args.expires,
        )
    except ValueError as error:
        print(f"Cannot make the access key: {error}", file=sys.stderr)
        return 2
    print(token)
    return 0


def cmd_revoke(args: argparse.Namespace) -> int:
    org_file = _org_key_path(args)
    if not org_file.exists():
        print(f"No company key at {org_file}. Run `org-init` first.", file=sys.stderr)
        return 2
    store = Path(args.org_dir).expanduser() / f"{args.org_id}-revoked.json"
    known: list[str] = json.loads(store.read_text(encoding="utf-8")) if store.exists() else []
    known = sorted(set(known) | {args.member_id})
    try:
        token = sign_revocations(load_private(org_file), args.org_id, known)
    except ValueError as error:
        print(f"Cannot revoke: {error}", file=sys.stderr)
        return 2
    store.write_text(json.dumps(known), encoding="utf-8")
    print(token)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "--key-file", default=str(DEFAULT_KEY_FILE), help="where the private key lives"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init", help="make the key pair (once)")
    init.add_argument("--force", action="store_true", help="replace an existing private key")
    init.set_defaults(run=cmd_init)
    sign = sub.add_parser("sign", help="print a licence key for a buyer")
    sign.add_argument("--name", required=True, help="the buyer's name as it should appear")
    sign.add_argument("--expires", help="last valid day, e.g. 2027-12-31 (default: never)")
    sign.add_argument("--plan", choices=["pro", "enterprise"], default="pro")
    sign.add_argument("--org", help="the organisation's name (shown on the Pro page)")
    sign.add_argument(
        "--seats", type=int, help="how many people the licence is for (shown, not counted)"
    )
    sign.set_defaults(run=cmd_sign)
    check = sub.add_parser("check", help="check a licence key against the site's public key")
    check.add_argument("key")
    check.set_defaults(run=cmd_check)
    for name, helptext in (
        ("org-init", "make a company key and print its certificate (signed by the owner key)"),
        ("member", "print one unique Boss or Member access key (signed by the company key)"),
        ("revoke", "print the company's signed revocation list with one more member added"),
    ):
        sp = sub.add_parser(name, help=helptext)
        sp.add_argument("--org-id", required=True, help="lower-case id, e.g. acme")
        sp.add_argument("--org-dir", default=str(DEFAULT_ORG_DIR), help="where company keys live")
        if name == "org-init":
            sp.add_argument("--org-name", required=True)
            sp.add_argument("--expires", help="last valid day of the certificate (default: never)")
            sp.add_argument("--force", action="store_true")
            sp.set_defaults(run=cmd_org_init)
        elif name == "member":
            sp.add_argument("--role", choices=list(ROLES), required=True)
            sp.add_argument("--name", required=True)
            sp.add_argument("--scopes", help="comma list, a subset of the role's scopes")
            sp.add_argument("--expires", help="last valid day (default: never)")
            sp.set_defaults(run=cmd_member)
        else:
            sp.add_argument("--member-id", required=True)
            sp.set_defaults(run=cmd_revoke)
    args = parser.parse_args(argv)
    return int(args.run(args))


if __name__ == "__main__":
    raise SystemExit(main())
