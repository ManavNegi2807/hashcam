"""A simulated endpoint collector, explainable scoring, web enrichment and alerts.

Honest scope: the scenario events here are SIMULATED. The only real source is the opt-in collector
(`endpoint/collector.py`), which watches one folder and script-shell launches on the computer it
runs on and nothing else. What is real is everything after the event is reported: the gateway
records it, the rules score it and explain the score, TinyFish may be asked about a URL, and a
person signs before any account is isolated (the isolation itself is simulated). A score is a rule
sum, not a probability, and an alert is a signal for a person to review, never proof of
wrongdoing.
"""
