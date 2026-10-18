# Detection measurements (synthetic data only)

Made by `python tools/measure_endpoint.py --write docs/MEASUREMENTS.md`. Each seed is a fresh
labelled set of 800 events (200 attacks, about a quarter of them built to be hard; about
a tenth of the ordinary events look odd but are fine). The model is trained on separate ordinary
synthetic events.

**Read this first.** The events are made up by the author of the rules. The numbers are optimistic
and are **not** real-world performance. They show how the rules and the model compare on events
whose truth is known, and what each one misses. Precision is of the alerts raised; the false-alarm
rate is the share of ordinary events flagged. Thresholds are the ones the detectors already use;
nothing was tuned to improve a number.

| Detector | Seed | Precision | Recall | F1 | False-alarm rate | Hard attacks caught |
|---|---|---|---|---|---|---|
| rules | 11 | 0.74 | 0.84 | 0.79 | 0.10 | 0.20 |
| rules | 22 | 0.72 | 0.77 | 0.74 | 0.10 | 0.22 |
| rules | 33 | 0.72 | 0.76 | 0.74 | 0.10 | 0.21 |
| rules | 44 | 0.74 | 0.83 | 0.78 | 0.10 | 0.23 |
| rules | 55 | 0.73 | 0.81 | 0.76 | 0.10 | 0.20 |
| model | 11 | 0.65 | 0.31 | 0.42 | 0.06 | 0.28 |
| model | 22 | 0.65 | 0.28 | 0.39 | 0.05 | 0.20 |
| model | 33 | 0.56 | 0.25 | 0.35 | 0.07 | 0.18 |
| model | 44 | 0.60 | 0.27 | 0.37 | 0.06 | 0.19 |
| model | 55 | 0.62 | 0.30 | 0.40 | 0.06 | 0.22 |
| rules or model | 11 | 0.74 | 0.86 | 0.80 | 0.10 | 0.31 |
| rules or model | 22 | 0.72 | 0.78 | 0.75 | 0.10 | 0.24 |
| rules or model | 33 | 0.69 | 0.77 | 0.73 | 0.11 | 0.25 |
| rules or model | 44 | 0.73 | 0.84 | 0.78 | 0.10 | 0.26 |
| rules or model | 55 | 0.73 | 0.81 | 0.77 | 0.10 | 0.22 |

| Attack family (seed 11) | rules | model | rules or model |
|---|---|---|---|
| burst | 1.00 | 0.00 | 1.00 |
| burst_hard | 0.00 | 0.00 | 0.00 |
| exfil | 1.00 | 0.28 | 1.00 |
| exfil_hard | 0.00 | 0.20 | 0.20 |
| phishing | 1.00 | 1.00 | 1.00 |
| phishing_hard | 0.80 | 0.90 | 1.00 |
| shell | 1.00 | 0.00 | 1.00 |
| shell_hard | 0.00 | 0.00 | 0.00 |

Per event (this machine, one run): rules 30 microseconds, model 59 microseconds. Training the model took 6.4 s.
Ordinary-looking events that were flagged anyway (seed 11): rules: month_end_burst, nightly_backup; model: file_download, nightly_backup, url_click; rules or model: file_download, month_end_burst, nightly_backup, url_click.
