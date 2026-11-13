# Claude Route Watch

[![CI](https://github.com/majiayu000/claude-route-watch/actions/workflows/ci.yml/badge.svg)](https://github.com/majiayu000/claude-route-watch/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Explainable **routing scores** and local alerts for Claude traffic observed by Mihomo / Clash Verge. A single Python module, zero runtime dependencies, read-only controller access. CLI and callable scoring function included.

**A score is not an account-ban probability.** 100 means the observed connections matched your routing expectation with TUN enabled. It does not certify your IP reputation, physical location, account eligibility, or future access. No affiliation with Anthropic or MetaCubeX.

## Install and run

Python 3.10+ required. The current integration uses a **Unix socket**, auto-detects **Clash Verge on macOS**, and sends optional macOS notifications. Other Unix Mihomo installations can supply socket/config paths; live verification so far covers macOS only. Windows controller access is not implemented.

```sh
git clone https://github.com/majiayu000/claude-route-watch.git
cd claude-route-watch
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/claude-route-watch --expect 'YOUR FINAL PROXY NODE'
.venv/bin/claude-route-watch --expect 'YOUR FINAL PROXY NODE' --watch --notify
```

No PyPI release is available yet. Alternatively, run `python3 claude_route_watch.py --expect 'YOUR FINAL PROXY NODE'` without installing.

`--expect` is required. Use the actual **final node name**, not an outer group like `AI`. No node/group names are assumed. To stop, press Ctrl-C; nothing installs a daemon or starts on login.

For a custom Unix controller:

```sh
claude-route-watch --socket /path/to/mihomo.sock --config /path/to/config.yaml --expect 'YOUR FINAL PROXY NODE'
```

The config file is read only for its top-level scalar `secret`. `MIHOMO_SECRET` can supply/override the controller secret without exposing it in command-line arguments. Use your existing secure environment or config; do not commit credentials. The tool calls only `GET /configs` and `GET /connections`. It never changes selectors, terminates connections, queries your account, or sends API prompts.

## Scoring v1: higher means closer to the expected routing

This is an **explicit engineering heuristic**, not a formula published by Anthropic or calibrated against account-ban outcomes.

| Component | Points | Evidence |
| --- | ---: | --- |
| Expected route | 0–60 | `60 × matching Claude connections / observed Claude connections` |
| Endpoint consistency | 0 or 20 | All identified Claude connections use one final node |
| TUN coverage indicator | 0 or 20 | Mihomo reports TUN enabled; this does not prove all system traffic is captured |

Critical overrides apply **after** summing:

- Any identified Claude connection using `DIRECT`: **0**, regardless of normal connections.
- Any identified connection using an unexpected endpoint: **at most 39**.
- No identified Claude connections, missing chain data, or API failure: **`null` / unknown**, never a passing score. A confirmed direct connection still scores 0 even if another chain is missing.

Examples with TUN enabled:

| Snapshot | Score | Interpretation |
| --- | ---: | --- |
| All observed connections use the expected node | 100 | Observed routing matches |
| Expected node, TUN disabled | 80 | Observed route matches; capture coverage warning |
| Two expected + one unexpected | 39 | Mixed endpoints; capped after raw 60 |
| One unexpected node only | 20 | Consistent, but not the expected route |
| Many expected + one DIRECT | 0 | Confirmed direct connection |
| No connections / missing metadata | unknown | Insufficient evidence |

Every JSON report includes the score, three component values, observed count, actual route summaries, and warnings. Missing components stay `null`, without renormalizing the score. Warnings remain actionable even at 80. A score of 100 does not imply a representative sample: inspect the observed count and exercise the workflows you care about.

```python
from claude_route_watch import analyze

report = analyze(
    {"tun": {"enable": True}},
    {"connections": [{
        "metadata": {"host": "api.anthropic.com", "process": "claude"},
        "chains": ["My exit", "My group"],
    }]},
    expected="My exit",
)
assert report["score"] == 100
```

`analyze` is a pure function over Mihomo-shaped snapshots, and raises on malformed input; the CLI converts read/parse failures into unknown. It does not contact any service.

## Observation and alerts

Claude is identified by its CLI/Desktop process, native installation path, or Anthropic/Claude domains. This covers version-number process names and browser authentication to known domains. It excludes unrelated browser Sentry traffic. It does not classify arbitrary child `git`, `npm`, SSH, or MCP traffic as Claude identity traffic.

Watch mode samples every two seconds. Changed scores or warning sets produce JSON lines; unchanged state is quiet. Use `--interval` and `--duration` for a bounded observation. Notifications report warnings, unknown state, and recovery; zero connections is unknown, not evidence of account trouble. Exit codes: 0 observed OK, 1 warning, 2 unknown/invalid invocation.

```sh
claude-route-watch --test-notification
```

Notification Center permissions and Focus settings can hide a notification. A successful `osascript` call only proves submission. The terminal report remains available.

## Boundaries and privacy

- Only active connections visible to Mihomo are scored. Short-lived traffic between samples and connections bypassing Mihomo can be missed. No packet capture or TLS interception.
- Node-name consistency is not public-IP consistency. A node can change IP behind the same name. DNS leaks, IPv6 escapes, ASN/IP reputation, geography, latency, account status, and eligibility are **unmeasured** and do not receive invented points.
- This tool cannot determine why an account is restricted, or infer that a working network makes an account safe. Anthropic lists multiple [suspension reasons](https://support.claude.com/en/articles/8241253-safeguards-warnings-and-appeals).
- No telemetry, cloud backend, or automatic report upload. JSON output includes destination hosts and node names; redact reports before sharing. Secrets and process paths are not emitted.

## Validation and design decision

Run `python3 -m unittest discover -v`. Scoring tests cover direct-traffic dilution, wrong-node caps, mixed old/current routes, unknown evidence, version-number processes, browser authentication, unrelated telemetry, TUN-off warnings, and API failure without credential leakage. CI builds the distribution and tests Python 3.10/3.13 on macOS/Linux; its badge reflects actual workflow status, not a claim of live cross-platform acceptance.

The predecessor was exercised against live macOS Clash Verge API/download/log/bridge connections. The scoring version was exercised on the same macOS controller: 44 visible Claude-process/domain connections matched the specified node and scored 100. The installed CLI was also checked independently. Real direct-traffic and route-change incidents are exercised by injected snapshots, not by changing a user's network. Notification display, long-running behavior, IDE login refresh, and non-macOS live controllers remain unverified.

Decision: ship a small local observer with explainable routing points; do not publish a ban predictor. Unknown evidence must never become a green score. Do not use this as a complete network-enforcement boundary.

Sources: [Mihomo controller API](https://wiki.metacubex.one/en/api/), [Claude Code network requirements](https://code.claude.com/docs/en/network-config). The weights and overrides above are this project's choices, not claims made by those sources.
