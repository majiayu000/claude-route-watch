# Claude Route Watch

[![CI](https://github.com/majiayu000/claude-route-watch/actions/workflows/ci.yml/badge.svg)](https://github.com/majiayu000/claude-route-watch/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Explainable **routing scores** and local alerts for Claude traffic observed by Mihomo / Clash Verge. A small Python library with a native macOS app and read-only controller access. The CLI has zero runtime dependencies. CLI and callable scoring function included. Optional route-verified exit probes and source-attributed IP intelligence are available in v0.2.0.

**A score is not an account-ban probability.** 100 means the observed connections matched your routing expectation with TUN enabled. It does not certify your IP reputation, physical location, account eligibility, or future access. No affiliation with Anthropic or MetaCubeX.

## Terminal menu / 终端一键入口

With Python 3.10+ installed, run the standalone `sh claude-route-watch.sh`, or use `sh run.sh` from this checkout or an extracted terminal bundle. No pip packages, root privileges, or Clash installation are needed for **this machine's IP check**. The menu itself makes no external requests:

```text
1. 检查当前机器的公网 IP 与信誉（无需 Clash）
2. 检查 Claude 在 Clash 中的实际线路
3. 持续观察 Claude 线路变化
0. 返回 / 退出
```

Choose a number. Route checks discover Clash Verge's controller, available final nodes and HTTP/mixed port. You explicitly choose the expected node; the currently observed route is only a hint. Optional proxy/IP intelligence requires another explicit choice. Ctrl-C exits the program, including any pending watch query; nothing runs in the background afterward. For another Unix Mihomo installation, use `sh run.sh --menu --socket /path/to/mihomo.sock --config /path/to/config.yaml`.

The single-file `claude-route-watch.pyz` runs anywhere with Python 3.10+ and standard TLS certificates. It does not include a Python interpreter. To build the bundle locally: `python3 scripts/build-terminal.py`. The output under `dist/` includes the standalone `.sh`, the `.pyz`, a ZIP with `run.sh`, documentation, and SHA256SUMS. The standalone `.sh` embeds the program, needs no extraction, and cleans up its temporary program file when it exits. This terminal bundle has not been published as a release yet; do not download `run.sh` alone or pipe it from a URL without the accompanying program.

For unattended VPS checks:

```sh
sh claude-route-watch.sh --ip         # readable report
sh claude-route-watch.sh --ip --json  # structured output
sh claude-route-watch.sh --ip --details # full source evidence
```

`--ip` directly queries ipify and ipapi.is, plus authenticated providers only when their existing credential environment variables are configured. HTTP proxy environment variables are ignored in this mode; system VPN/TUN routing still applies. It observes one echo-service exit, not every IPv4/IPv6 exit or Anthropic's view. Reports stay local with no automatic upload. Missing paid-source keys are shown as **未配置，未检测**; unavailable evidence never becomes a passing score. Exit codes: 0 complete source coverage, 1 complete coverage with advisories, 2 incomplete/unknown evidence (including a successful anonymous basic lookup with missing advanced sources).

The default terminal report is a fixed-region dashboard: a verdict bar on the first line, then exit identity and the Claude route (side by side from 80 columns, stacked below that), the reputation sources with the A–D line, the check steps, and the keys. While a check runs, the same regions fill in from real progress (echo sample n/3, which source is being queried); no percentage is invented. Watch mode redraws the dashboard in place instead of appending. With `--reputation`, the exit echo goes through the node Claude is actually using. In watch mode the first stable exit through your chosen node becomes this run's baseline (memory only): a different node with the same exit IP is shown as a record, not a warning, while a changed exit IP or a direct connection is. Watch from the menu on macOS also sends one system notification when the dashboard turns red (exit changed, direct connection, C/D reputation) and again only if the red reason changes; incomplete evidence stays on screen without a notification. A one-shot check has no baseline, so a different node stays yellow and shows the observed exit for you to confirm. JSON adds `node_changes` and `exit`; the routing score itself is unchanged. In the menu, the result stays visible until you press Enter; `d` opens source details from the same response, without another query. Unknown field lists, credentials guidance and scoring rules live in details. ANSI colors follow the terminal theme and automatically disappear for redirected output, `TERM=dumb` or `NO_COLOR`. Narrow terminals use stacked source rows; long summary values are clipped with an ellipsis, while details/JSON keep the full data.

The report also shows our **A–D evidence grade v1**, separate from routing points and source coverage. A means low risk in the checked sources, B means review signals, C strong signals, D very strong signals. All three providers must return their primary fields before a grade is assigned; an anonymous basic lookup therefore normally displays **资料不足，暂不评级**. Known adverse evidence remains visible even when a grade is withheld. We use the strongest signal, never average unrelated numbers. Datacenter/VPN labels alone do not lower the grade. This is our disclosed heuristic, not a calibrated platform-safety rating. See the [exact grading rules](docs/ip-reputation.md#our-a–d-evidence-grade-v1).

Decision: add the small menu and an explicit direct-IP path, reuse the routed observer, and retain source-attributed metrics. Add only an explained, versioned evidence grade; do not add an aggregate ban-risk score, automatic dependency installer, or benchmark suite. Basic usage must not require provider keys; a report must identify which exit it actually observed.

## Desktop app — no commands

**[Download the macOS Apple Silicon preview](https://github.com/majiayu000/claude-route-watch/releases/tag/v0.3.0-preview.1)**

1. Unzip, move **Claude Route Watch.app** into Applications, and double-click it. No Python, Terminal, or package installation is needed.
2. Keep Clash Verge running. The app discovers its controller, HTTP/mixed port, and Claude's current node. Confirm the suggested node with **开始监测** (Start monitoring).
3. For optional exit/IP intelligence, turn on **开启 IP 检查**. Basic ownership works without keys. Full provider keys can be entered in the optional panel; they stay in memory for this launch only.

The app remembers your explicitly chosen baseline, monitoring state, and notification preference. It never silently adopts a changed route. IP queries start off on each launch. Minimize the window to continue watching; closing it exits the app. No login service or hidden daemon is installed.

This preview is **ad-hoc signed, not Developer ID signed or notarized**. macOS may require approval for a downloaded app; do not disable Gatekeeper globally. The packaged preview targets Apple Silicon macOS and Clash Verge; Windows GUI/controller support is not implemented.

## Terminal verification (2026-11-16)

The packaged terminal was exercised on macOS arm64: opening the menu, discovering live Clash nodes, selecting an explicit baseline, rendering live Claude connections, watching, and Ctrl-C exit. An anonymous direct lookup returned a public echo IP and ownership/location; absent advanced sources stayed unconfigured/unknown. Controlled tests cover changed/missing routes, TLS failure, direct/proxy separation, missing keys, and noninteractive behavior. Linux arm64 was exercised in a local Python 3.13 Alpine container for tests, launcher/help, and offline unknown output. Real VPS installation, Linux live controllers, Linux amd64, Python 3.10 execution, authenticated source calls and long-running observation remain unverified.

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

For flag-based routing checks, `--expect` is required. Without arguments, the interactive menu opens instead. Use the actual **final node name**, not an outer group like `AI`. No node/group names are assumed. To stop, press Ctrl-C; nothing installs a daemon or starts on login.

For a custom Unix controller:

```sh
claude-route-watch --socket /path/to/mihomo.sock --config /path/to/config.yaml --expect 'YOUR FINAL PROXY NODE'
```

The config file is read only for its top-level scalar `secret`. `MIHOMO_SECRET` can supply/override the controller secret without exposing it in command-line arguments. Use your existing secure environment or config; do not commit credentials. Controller access uses only `GET /configs`, `GET /connections`, and (for menu discovery) `GET /proxies`. Optional `--reputation` makes external read-only HTTPS probes/lookups, described below. It never changes selectors, terminates connections, queries your account, or sends API prompts.

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

Routing checks without `--reputation` make no third-party calls. Missing keys produce partial/skipped evidence, not a passing IP score. Routed source queries use an explicit loopback HTTP proxy; the separate `--ip` mode makes direct machine-IP queries. Source lookups run separately from the watch sampler, are cached, and respect provider cooldowns. The echo-service IP is not proof of the IP Anthropic sees.

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
