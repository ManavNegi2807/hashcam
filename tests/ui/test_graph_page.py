"""The graph on the audit page: the /api/graph route and the drawn picture.

The receipt summary is replaced by a fixed one so no signer or verifier is needed; the graph code,
the server route and the page are all real. With ABB_TEST_FALKORDB set, the same route is also
checked against a real FalkorDB.
"""

from __future__ import annotations

import http.client
import json
import os
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

import services.dashboard.server as server_module
from services.dashboard.server import Config, serve
from services.graph.store import FalkorStore
from tests.graph.test_graph import summary

FALKOR = os.environ.get("ABB_TEST_FALKORDB")
NAME = "sample.abbreceipt"


@pytest.fixture()
def receipts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (tmp_path / NAME).write_bytes(b"not read: summarize is replaced below")
    monkeypatch.setattr(server_module, "summarize", lambda _path: summary())
    return tmp_path


def start(config: Config) -> Iterator[int]:
    server = serve(config, 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


@pytest.fixture()
def port(receipts: Path) -> Iterator[int]:
    yield from start(Config(receipts=receipts, keys=None, abb="abb"))


def get(port: int, path: str) -> tuple[int, Any]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("GET", path)
    response = conn.getresponse()
    body = response.read()
    conn.close()
    return response.status, json.loads(body)


def test_without_a_database_the_graph_is_drawn_from_the_receipt_and_says_so(port: int) -> None:
    status, graph = get(port, f"/api/graph?name={NAME}")
    assert status == 200
    assert graph["source"] == "receipt"
    assert "not connected" in graph["note"]
    assert len(graph["nodes"]) > 3 and graph["edges"]


def test_an_unknown_receipt_has_no_graph(port: int) -> None:
    status, _ = get(port, "/api/graph?name=missing.abbreceipt")
    assert status == 404


def test_an_unreachable_database_falls_back_and_says_so(receipts: Path) -> None:
    config = Config(
        receipts=receipts, keys=None, abb="abb", graph=FalkorStore("redis://127.0.0.1:1")
    )
    for port in start(config):
        status, graph = get(port, f"/api/graph?name={NAME}")
    assert status == 200
    assert graph["source"] == "receipt"
    assert "unavailable" in graph["note"]


@pytest.mark.skipif(not FALKOR, reason="set ABB_TEST_FALKORDB")
def test_with_falkordb_connected_the_graph_comes_back_from_the_database(receipts: Path) -> None:
    config = Config(receipts=receipts, keys=None, abb="abb", graph=FalkorStore(str(FALKOR)))
    for port in start(config):
        status, graph = get(port, f"/api/graph?name={NAME}")
    assert status == 200
    assert graph["source"] == "falkordb"
    assert graph["actions_by_status"] == {"approved": 1, "blocked": 1, "succeeded": 1}


def _playwright() -> object:
    return pytest.importorskip("playwright.sync_api")


@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_the_page_draws_the_graph_readably(port: int, scheme: str) -> None:
    sync_api = _playwright()
    axe_module = pytest.importorskip("axe_playwright_python.sync_playwright")
    with sync_api.sync_playwright() as p:  # type: ignore[attr-defined]
        browser = p.chromium.launch()
        page = browser.new_page(color_scheme=scheme, viewport={"width": 1200, "height": 900})
        failures: list[str] = []
        page.on("pageerror", lambda e: failures.append(str(e)))
        page.goto(f"http://127.0.0.1:{port}/")
        page.evaluate(f"graphView.show('{NAME}')")
        page.wait_for_selector("#graph:not([hidden]) svg.graphsvg", timeout=10000)
        page.wait_for_timeout(1200)  # let the entrance animation finish
        facts = page.evaluate(
            """() => ({
                nodes: document.querySelectorAll('#graph .gnode').length,
                edges: document.querySelectorAll('#graph .gedge').length,
                listed: document.querySelectorAll('#graph .graphlist li').length,
                note: document.getElementById('graph-note').textContent,
                text: document.getElementById('graph').innerText,
            })"""
        )
        overflow = page.evaluate("document.documentElement.scrollWidth > innerWidth")
        results = axe_module.Axe().run(page)
        violations = [(v["id"], v["impact"]) for v in results.response["violations"]]
        browser.close()
    assert failures == []
    assert facts["nodes"] >= 6 and facts["edges"] >= 6
    assert facts["listed"] == facts["edges"]  # every link is also written out as text
    assert "drawn from the receipt" in facts["note"]
    assert "blocked" in facts["text"] and "approved" in facts["text"]
    assert overflow is False
    assert violations == [], violations
