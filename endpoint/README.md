# endpoint — endpoint review (events, rules, alerts, evidence)

**Status:** `TESTED` end to end with real signing and the real verifier (`tests/endpoint/`, `tools/demo_endpoint.py`). The events are **simulated**,
except those from the opt-in collector, and the account isolation is **simulated**. TinyFish's answers are a scripted fake in the tests.
Not a security product. **Requirements:** R-ANO-05 (no circularity), R-ANO-11, R-UI-05.

A score is a rule sum, not a probability, and an alert is a signal for a person to review, never proof of wrongdoing.

| File | What it does |
|---|---|
| `events.py`, `synthetic.py` | Made-up events and scenarios; labelled synthetic data for measuring. |
| `scoring.py` | Explainable rules, each with a plain-words reason. No rule reads a policy decision or an allowlist. |
| `model.py` | Optional Isolation Forest, trained every time on synthetic events; advisory only; absent if scikit-learn is not installed. |
| `investigate.py` | Asks TinyFish Search and Fetch about a URL through the gateway. A missing answer is `UNKNOWN`, never "safe". |
| `alerts.py` | Reads alerts back out of a receipt; nothing is scored again and nothing is decided. |
| `collector.py` | Opt-in collector for **this** computer: new files in one folder, script-shell launches, links written to a file. Never reads file contents or browser history. |
| `measure.py` | Measures the rules and the model on labelled synthetic events. Numbers are optimistic (same author) and say nothing about real traffic. |

Run: `python tools/demo_endpoint.py ...`, `python tools/endpoint_daemon.py ...` (see `docs/DEMO.md`, "Endpoint review").
