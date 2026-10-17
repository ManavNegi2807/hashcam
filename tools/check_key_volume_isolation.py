"""Check that no key volume is shared, and that the signer stays unreachable.

`R-OPS-03` and `R-SIG-01` say the signer's key volume must be separate and must
not be mounted into any other service. That is a property of the deployment
file, so it is checked as one: a reviewer should not have to notice it.

Rules enforced here, over `deploy/docker-compose.yml`:

1. a volume whose name ends in `_keys` is mounted by **at most one** service;
2. `signer_keys` is mounted only by `signer`, and read-only;
3. the signer publishes **no** host ports;
4. the signer is not on the database network, so it cannot reach PostgreSQL;
5. no service passes a database URL or password to the signer.

Run it directly, or through `tests/security/test_compose_isolation.py`:

    python tools/check_key_volume_isolation.py deploy/docker-compose.yml
"""

from __future__ import annotations

import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - reported, not worked around
    print("this check needs PyYAML (see requirements-dev.txt)", file=sys.stderr)
    raise SystemExit(2) from None

DEFAULT_FILE = Path(__file__).resolve().parents[1] / "deploy" / "docker-compose.yml"
DATABASE_NETWORK = "data"
FORBIDDEN_FOR_SIGNER = ("ABB_DB", "POSTGRES", "DATABASE_URL", "DSN")


def volume_name(mount: object) -> str | None:
    """The named volume in a compose mount, or `None` for a bind mount."""
    if not isinstance(mount, str):
        # The long syntax: {type, source, target, read_only}
        if isinstance(mount, dict) and mount.get("type") == "volume":
            source = mount.get("source")
            return str(source) if source else None
        return None
    source = mount.split(":", 1)[0]
    if source.startswith((".", "/", "~")) or "/" in source:
        return None
    return source


def is_read_only(mount: object) -> bool:
    if isinstance(mount, str):
        return mount.rstrip().endswith((":ro", ":ro,z", ":ro,Z"))
    return bool(isinstance(mount, dict) and mount.get("read_only"))


def check(path: Path) -> list[str]:
    """Return a list of problems; empty means the file is as it should be."""
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    services = document.get("services", {}) or {}
    problems: list[str] = []

    # 1 and 2: who mounts which key volume.
    mounted_by: dict[str, list[str]] = {}
    for name, service in services.items():
        for mount in service.get("volumes", []) or []:
            volume = volume_name(mount)
            if volume and volume.endswith("_keys"):
                mounted_by.setdefault(volume, []).append(name)
                if volume == "signer_keys" and not is_read_only(mount):
                    problems.append(
                        f"{name} mounts signer_keys writable; the signer needs it read-only"
                    )

    for volume, users in mounted_by.items():
        if len(users) > 1:
            problems.append(
                f"{volume} is mounted by {', '.join(sorted(users))}: a key volume belongs "
                f"to exactly one service (R-OPS-03)"
            )

    if "signer" in services:
        if mounted_by.get("signer_keys") != ["signer"]:
            problems.append(
                "signer_keys must be mounted by the signer and by nothing else, but is "
                f"mounted by {mounted_by.get('signer_keys') or 'nobody'}"
            )

        signer = services["signer"]

        # 3: no published port.
        if signer.get("ports"):
            problems.append(
                f"the signer publishes {signer['ports']}; it must be reachable only from "
                f"the ingestion service (R-OPS-04)"
            )

        # 4: not on the database network.
        networks = signer.get("networks") or []
        names = list(networks) if isinstance(networks, list) else list(networks.keys())
        if DATABASE_NETWORK in names:
            problems.append(
                f"the signer is on the {DATABASE_NETWORK} network; it has no database "
                f"credentials and should not be able to reach one (R-SIG-02)"
            )

        # 5: nothing database-shaped in its environment.
        environment = signer.get("environment") or {}
        keys = (
            environment.keys()
            if isinstance(environment, dict)
            else [item.split("=", 1)[0] for item in environment]
        )
        for key in keys:
            if any(marker in str(key).upper() for marker in FORBIDDEN_FOR_SIGNER):
                problems.append(f"the signer is given {key}; it must have no database access")

        # The signer must not be handed the private ingestion key either: it
        # only needs the public half to check attestations.
        for mount in signer.get("volumes", []) or []:
            if volume_name(mount) == "ingestion_keys":
                problems.append("the signer mounts ingestion_keys; it needs only the public key")

    return problems


def main(argv: list[str]) -> int:
    path = Path(argv[1]) if len(argv) > 1 else DEFAULT_FILE
    if not path.is_file():
        print(f"no such compose file: {path}", file=sys.stderr)
        return 2
    problems = check(path)
    if problems:
        for problem in problems:
            print(f"PROBLEM {problem}")
        print(f"{len(problems)} problem(s) in {path.name}")
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
