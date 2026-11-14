# Claude Route Watch

[![CI](https://github.com/majiayu000/claude-route-watch/actions/workflows/ci.yml/badge.svg)](https://github.com/majiayu000/claude-route-watch/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Explainable **routing scores** and local alerts for Claude traffic observed by Mihomo / Clash Verge. A small Python library with a native macOS app and read-only controller access. The CLI has zero runtime dependencies. CLI and callable scoring function included. Optional route-verified exit probes and source-attributed IP intelligence are available in v0.2.0.

**A score is not an account-ban probability.** 100 means the observed connections matched your routing expectation with TUN enabled. It does not certify your IP reputation, physical location, account eligibility, or future access. No affiliation with Anthropic or MetaCubeX.

## Desktop app — no commands

**[Download the macOS Apple Silicon preview](https://github.com/majiayu000/claude-route-watch/releases/tag/v0.3.0-preview.1)**

1. Unzip, move **Claude Route Watch.app** into Applications, and double-click it. No Python, Terminal, or package installation is needed.
2. Keep Clash Verge running. The app discovers its controller, HTTP/mixed port, and Claude's current node. Confirm the suggested node with **开始监测** (Start monitoring).
3. For optional exit/IP intelligence, turn on **开启 IP 检查**. Basic ownership works without keys. Full provider keys can be entered in the optional panel; they stay in memory for this launch only.

The app remembers your explicitly chosen baseline, monitoring state, and notification preference. It never silently adopts a changed route. IP queries start off on each launch. Minimize the window to continue watching; closing it exits the app. No login service or hidden daemon is installed.

This preview is **ad-hoc signed, not Developer ID signed or notarized**. macOS may require approval for a downloaded app; do not disable Gatekeeper globally. The packaged preview targets Apple Silicon macOS and Clash Verge; Windows GUI/controller support is not implemented.

## CLI and library installation (developers)

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

The config file is read only for its top-level scalar `secret`. `MIHOMO_SECRET` can supply/override the controller secret without exposing it in command-line arguments. Use your existing secure environment or config; do not commit credentials. Controller access uses only `GET /configs` and `GET /connections`. Optional `--reputation` makes external read-only HTTPS probes/lookups, described below. It never changes selectors, terminates connections, queries your account, or sends API prompts.

## Optional IP reputation (v0.2.0)

```sh
.venv/bin/claude-route-watch --expect 'YOUR FINAL PROXY NODE' --reputation \
  --proxy http://127.0.0.1:7890
```

Three fresh echo connections are correlated with Mihomo by socket address/port and hostname. A probe that cannot be attributed to the expected final node stops reputation lookup. Every observed exit IP gets a separate report, preserving vendor data rather than inventing a ban score.

- **ipapi.is**: location/ASN ownership; optional keyed VPN/proxy/datacenter/Tor/abuse flags and labeled network-wide abuse fractions.
- **Scamalytics v3**: original fraud score, ISP score, risk labels, proxy types and source-attributed blacklist evidence; user credentials required.
- **AbuseIPDB**: original abuse confidence, 90-day report counts and report age; user key required.
- IP stability/change, country/flag disagreements, explicit nulls, missing credentials, source errors, timestamps and cache age.

No `--reputation`, no third-party calls. Missing keys produce partial/skipped evidence, not a passing IP score. All source queries use an explicit loopback HTTP proxy. Source lookups run separately from the watch sampler, are cached, and respect provider cooldowns. The echo-service IP is not proof of the IP Anthropic sees.

**[Full IP-reputation guide](docs/ip-reputation.md)**: credential variables, attribution, score meanings, report fields, failure cases, alerts, cache/quotas, library API, and live versus synthetic acceptance evidence.

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

Watch mode samples every two seconds. Changed scores or warning sets produce JSON lines; unchanged routing state is quiet. Optional IP intelligence also emits timestamped refresh-start/completion reports. Use `--interval` and `--duration` for a bounded observation. Notifications report warnings, unknown state, and recovery; zero connections is unknown, not evidence of account trouble. Routing-only exit codes: 0 observed OK, 1 warning, 2 unknown/invalid invocation. With IP intelligence enabled, incomplete source coverage also returns 2; see the full guide for priorities.

```sh
claude-route-watch --test-notification
```

Notification Center permissions and Focus settings can hide a notification. A successful `osascript` call only proves submission. The terminal report remains available.

## Boundaries and privacy

- Only active connections visible to Mihomo are scored. Short-lived traffic between samples and connections bypassing Mihomo can be missed. No packet capture or TLS interception.
- Node-name consistency is not public-IP consistency. A node can change IP behind the same name. Optional IP intelligence observes echo-service exits and vendor-reported ownership, geography and reputation separately. DNS leaks, independent IPv6 escapes, latency, account status, and eligibility remain **unmeasured** and do not receive invented points.
- This tool cannot determine why an account is restricted, or infer that a working network makes an account safe. Anthropic lists multiple [suspension reasons](https://support.claude.com/en/articles/8241253-safeguards-warnings-and-appeals).
- No project telemetry, cloud backend, or automatic report upload. Opt-in IP checks contact third-party services with the queried public IP and any configured API account credentials; see the guide before enabling. JSON output includes destination hosts and node names; redact reports before sharing. Secrets and process paths are not emitted.

## Validation and design decision

Run `python3 -m unittest discover -v`. Scoring tests cover direct-traffic dilution, wrong-node caps, mixed old/current routes, unknown evidence, version-number processes, browser authentication, unrelated telemetry, TUN-off warnings, and API failure without credential leakage. CI builds the distribution and tests Python 3.10/3.13 on macOS/Linux; its badge reflects actual workflow status, not a claim of live cross-platform acceptance.

The predecessor was exercised against live macOS Clash Verge API/download/log/bridge connections. The scoring version was exercised on the same macOS controller: 44 visible Claude-process/domain connections matched the specified node and scored 100. The installed CLI was also checked independently. The v0.2.0 exit-probe and anonymous-source behavior were exercised separately; authenticated sources remain validated with synthetic responses only. Real direct-traffic and route-change incidents are exercised by injected snapshots, not by changing a user's network. Notification display, long-running behavior, IDE login refresh, and non-macOS live controllers remain unverified.

Decision: ship a small local observer with explainable routing points; do not publish a ban predictor. Unknown evidence must never become a green score. Do not use this as a complete network-enforcement boundary.

Sources: [Mihomo controller API](https://wiki.metacubex.one/en/api/), [Claude Code network requirements](https://code.claude.com/docs/en/network-config). The weights and overrides above are this project's choices, not claims made by those sources.
