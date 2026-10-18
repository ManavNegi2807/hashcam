"""FalkorDB as the place the graph lives, reached over the Redis protocol on this computer.

Only a loopback address is accepted: this database holds a view of runs and has no business being
reachable from anywhere else. Every value reaches the database as a query parameter, never spliced
into the query text. If the database is down, callers get `GraphUnavailable` and fall back to
showing the same graph straight from the receipt, labelled as such.
"""

from __future__ import annotations

from typing import Any

from services.graph.build import LABELS, RELATIONS

LOOPBACK = {"127.0.0.1", "localhost", "::1"}


class GraphUnavailable(Exception):
    """FalkorDB is not configured, not reachable, or refused the query."""


def parse_url(url: str) -> tuple[str, int]:
    """`redis://127.0.0.1:6390` -> ("127.0.0.1", 6390). Anything not on this computer is refused."""
    rest = url.split("://", 1)[1] if "://" in url else url
    host, _, port = rest.rpartition(":")
    if not host or not port.isdigit():
        raise GraphUnavailable("the FalkorDB address must look like redis://127.0.0.1:6390")
    if host not in LOOPBACK:
        raise GraphUnavailable("FalkorDB is only used on this computer (127.0.0.1)")
    return host, int(port)


class FalkorStore:
    def __init__(self, url: str) -> None:
        self._host, self._port = parse_url(url)

    def _graph(self, run_id: str) -> Any:
        try:
            from falkordb import FalkorDB  # type: ignore[import-untyped]
        except ImportError as exc:
            raise GraphUnavailable("the falkordb Python package is not installed") from exc
        try:
            client = FalkorDB(host=self._host, port=self._port, socket_connect_timeout=3)
            return client.select_graph("hascham-" + run_id)
        except Exception as exc:  # any connection problem means "not available"
            raise GraphUnavailable("FalkorDB did not answer") from exc

    def save(self, run_id: str, graph: dict[str, list[dict[str, Any]]]) -> None:
        """Replace this run's graph. Rebuilding from the receipt is always safe."""
        handle = self._graph(run_id)
        try:
            try:
                handle.delete()
            except Exception:
                handle = self._graph(run_id)
            for label in LABELS:
                rows = [n for n in graph["nodes"] if n["label"] == label]
                if rows:
                    handle.query(f"UNWIND $rows AS r CREATE (n:{label}) SET n = r", {"rows": rows})
            for relation in RELATIONS:
                rows = [e for e in graph["edges"] if e["type"] == relation]
                if rows:
                    handle.query(
                        "UNWIND $rows AS r MATCH (a {id: r.src}), (b {id: r.dst}) "
                        f"CREATE (a)-[:{relation}]->(b)",
                        {"rows": rows},
                    )
        except Exception as exc:
            raise GraphUnavailable("FalkorDB refused the query") from exc

    def load(self, run_id: str) -> dict[str, Any]:
        """Read the graph BACK from the database, plus a question answered by the database."""
        handle = self._graph(run_id)
        try:
            node_rows = handle.ro_query("MATCH (n) RETURN labels(n)[0], properties(n)").result_set
            edge_rows = handle.ro_query("MATCH (a)-[r]->(b) RETURN a.id, type(r), b.id").result_set
            counts = handle.ro_query(
                "MATCH (a:Action) RETURN a.status, count(a) ORDER BY a.status"
            ).result_set
        except Exception as exc:
            raise GraphUnavailable("FalkorDB refused the query") from exc
        return {
            "nodes": [{"label": label, **props} for label, props in node_rows],
            "edges": [{"src": s, "type": t, "dst": d} for s, t, d in edge_rows],
            "actions_by_status": {str(status): int(n) for status, n in counts},
        }
