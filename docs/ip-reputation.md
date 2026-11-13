# IP reputation and exit evidence

This feature answers two separate questions: **which public IP did a route-verified echo request use**, and **what do external intelligence providers report about that IP**? It does not expose Anthropic's risk decisions or predict account suspension.

## Enable explicitly

```sh
claude-route-watch --expect 'YOUR FINAL NODE' --reputation \
  --proxy http://127.0.0.1:7890

claude-route-watch --expect 'YOUR FINAL NODE' --watch --notify \
  --reputation --proxy http://127.0.0.1:7890
```

Use your client's actual HTTP/mixed port. It must be an explicit **loopback HTTP proxy**, not its SOCKS port or controller port. There is no inferred proxy port or silent direct fallback. `CLAUDE_ROUTE_PROXY` can provide the URL instead of `--proxy`, which is preferable if the local proxy requires credentials. HTTP CONNECT basic authentication is supported. Do not paste real credentials into public issues or shell examples.

The Unix controller still needs to be available; use the existing `--socket`, `--config`, or `MIHOMO_SECRET` options when auto-discovery does not apply. A remote HTTP proxy cannot be attributed to the local controller and is not supported by this probe.

Without `--reputation`, no exit or provider requests are made. The original routing-only command remains usable without provider accounts.

## 1. Verify the route before trusting the IP

For each of three samples the tool:

1. Opens a fresh HTTP CONNECT tunnel through the chosen local proxy to `api64.ipify.org:443`.
2. Completes ordinary certificate-verified TLS to the echo service.
3. While that socket is open, reads Mihomo's connections and matches **source address + source port + echo hostname + destination port**. Looking up a hostname alone could accidentally select another process's connection.
4. Requires exactly one matching entry and the expected final node in its chain. A wrong node, DIRECT, duplicate match, missing chain, or missing connection makes the sample unverified.
5. Only after that check, requests the echo response and validates its public IPv4/IPv6 address.

If any sample is unverified, the check is `unknown` and **no reputation lookup is made**. IPs from individually verified samples remain visible as partial evidence; they do not make the entire probe pass.

The echo uses the dual-stack ipify endpoint. This does not independently test both IPv4 and IPv6 or detect DNS/WebRTC leaks. TLS certificates are never ignored, redirects are not followed, and system proxy variables do not override the explicit tunnel.

### What the attribution actually proves

`verified` means the echo requests used the expected named Mihomo node. An active Claude snapshot using that same node is described as `same_expected_node_observed_not_same_ip_proof`. It is **not proof of the IP Anthropic saw**: destination-dependent proxy pools and different address families can still produce different egress IPs.

A group named `AI` and a group named `Proxies` may select the same final node. The probe compares that final node, not the group name. Conversely, selecting the same group does not prove that all its connections used the same node.

### Stability and change evidence

- `observed_stable: true`: all three successfully attributed echo requests returned one IP during the recorded short window. This is not a guarantee of a static IP.
- `observed_stable: false`: more than one IP was returned; **every observed IP** is looked up separately.
- `observed_stable: null`: a complete route-verified sample window was unavailable.
- `change_since_previous_check`: compares verified IP sets across checks in the same process. The first check has `changed: null`; no earlier state is invented or backfilled.

No history database is created. To retain observations, redirect JSON lines to your own private log. IPs, node names, and destination hosts are sensitive when you share logs.

## 2. Supply your own optional provider credentials

Credentials are read from environment variables only; the program never writes `.env`, shell profiles, or credential files. Configure them in your existing secure environment. No shared key is embedded in the package or repository.

| Environment variable | Purpose | If absent |
| --- | --- | --- |
| `IPAPI_IS_KEY` | Full ipapi.is intelligence | Anonymous ownership/location lookup; security fields stay unknown |
| `SCAMALYTICS_USERNAME` | Scamalytics account username | Source skipped unless both username and key are present |
| `SCAMALYTICS_KEY` | Scamalytics v3 key | Source skipped |
| `SCAMALYTICS_REGION` | `us` (default) or `eu`, matching the account's assigned API node | US API node selected; wrong account region may fail authentication |
| `ABUSEIPDB_KEY` | AbuseIPDB read-only CHECK API | Source skipped |

Missing keys are reported as `skipped`, with the missing variable **names**, never their values. A rejected configured key reports an error: it is not silently retried anonymously.

The opt-in transmits the observed IP to ipify and configured intelligence services. Providers can also see the network address used to query them and their API account identity. No Claude credentials, prompts, files, transcripts, or process paths are sent. Queries go through the explicit TLS tunnel; there is no project-operated backend or automatic report upload.

## 3. Read each source in its own terms

### ipapi.is

- Ownership and location: country name/code when provided, region, city, ASN, announcing organization, company/network type, prefix, registry, and ASN registration country.
- Address labels: datacenter, VPN, open proxy, Tor, observed abuser, mobile, satellite, and anycast. Missing labels are `null`, never `false`.
- `company.abuser_score`: the provider's labeled abuse fraction for a company's **network**.
- `asn.abuser_score`: its abuse fraction over an **ASN's IPv4 routes**.

Those network fractions are not per-IP fraud scores. The ASN's registration country is separate from the IP's geolocation. Neither the registry nor a non-US location is used as a hard failure rule.

The current anonymous response contains basic ownership/location but not security detection flags. It may supply an ASN label instead of a structured ASN object, and a country name without a code; these remain labeled as such instead of being guessed into missing fields. Anonymous results therefore have `partial` coverage.

Keyed queries use POST with the key in the JSON body, keeping it out of the request URL.

### Scamalytics v3

- Original `scamalytics_score` (0–100) and vendor risk label, where a larger value means more vendor-assessed fraud risk.
- Separate ISP-wide score/label; it is not substituted for the IP score.
- Datacenter, VPN, residential proxy, iCloud Private Relay, and external-blacklist flags when supplied.
- Source-labeled secondary evidence from FireHOL, IPsum, Spamhaus DROP, and x4bnet.
- MaxMind GeoLite2 country/region/city/ASN fields as supplied through Scamalytics.
- Remaining credits, when returned; this is the vendor's approximate accounting.

Paid-plan placeholder text becomes `null` rather than a real organization name. A test-mode response is not accepted as live reputation evidence. The API requires its username and key in the URL; the program does not emit request URLs or raw exception/body text that could reveal them.

The provider's IP score is its own fraud signal. It is not a Claude-ban probability and is not converted into a new safety score. This library surfaces medium/high/very-high vendor labels as review advisories, not instructions to block users.

### AbuseIPDB

- Original `abuseConfidenceScore` (0–100), with its report-based meaning preserved.
- Report count, distinct reporters, last report time, and the queried **90-day** report window.
- ISP, usage type, country, Tor label, and whitelist value when supplied.
- Geolocation provenance: IPinfo via AbuseIPDB.

Zero reports or zero confidence is not proof of safety. A whitelist value of `null` is not `false`. Report age/count matter alongside the score. The program uses only the GET CHECK endpoint, authenticating with a header; it never submits abuse reports or requests report comments.

### Source links

[ipapi.is documentation](https://ipapi.is/developers.html), [Scamalytics v3 documentation](https://docs.scamalytics.com/ip-fraud-risk-api/v3/), [AbuseIPDB documentation](https://docs.abuseipdb.com/), [ipify API](https://www.ipify.org/), [Mihomo controller API](https://wiki.metacubex.one/en/api/).

Provider plans, fields, and quotas can change; these links are the authority. Do not scrape vendor web pages as a replacement for their authenticated APIs.

## 4. Coverage, disagreements, and errors

### Per-provider status

| Status | Meaning |
| --- | --- |
| `ok` | The expected primary fields were returned; optional fields can still be null |
| `partial` | Some information is usable, but primary fields are missing |
| `skipped` | Required credentials are absent; no request made |
| `rate_limited` | HTTP 429, exhausted credits, or an active provider cooldown |
| `error` | Transport/TLS, authentication, malformed response, non-live data, provider application error, or returned-IP mismatch |

Application-level errors in HTTP 200 responses are not accepted as successful lookups. Error reports include a safe reason, HTTP status when known, and exception class for transport/parser errors; they exclude raw bodies, request URLs, and credential values. Response sizes are bounded to one MiB. Redirects are treated as unsuccessful responses.

### Aggregate reputation coverage

- `complete`: all three sources returned their expected primary fields for every observed IP. This means **source coverage**, not complete network surveillance or a safe account.
- `partial`: at least one source returned usable data, while another source or field is unavailable.
- `unknown`: no usable source evidence, failed attribution, or unavailable monitoring.
- `pending`: a background watch check is still running.

Country comparison requires at least two available **country codes**. One source is insufficient, and a country name is not translated into a code using a homemade alias list. Different city names alone do not trigger a country-disagreement advisory. ASN registration country does not participate in the location comparison.

Disagreeing country codes and contradictory boolean proxy/network labels retain each provider's value. No majority vote, best-looking-source selection, or average score is computed. Several feeds may share upstream data; they are not independent votes.

### Alerts and exit codes

Review advisories include route-unverified probes, changing/rotating echo IPs, country or label disagreements, an IP flagged for abuse or an external blacklist, nonzero AbuseIPDB confidence, and a non-low Scamalytics risk label. A datacenter/VPN/residential label alone is informational: it is not automatically an account-risk verdict.

`--notify` submits macOS notifications for changed advisories, unavailable/incomplete evidence, and recovery. Source refresh timestamps alone do not resend identical alerts. Terminal JSON remains the evidence; Notification Center/Focus may hide submitted notifications.

The top-level `score` remains the original **routing-only** score. A route score of 100 alongside `reputation.status: partial` is intentionally possible; it must not be displayed as a 100-point IP-health result.

Exit code priorities:

1. Routing score unknown: **2**.
2. Known routing warning: **1**.
3. IP check pending/unknown: **2**.
4. Concrete IP review advisories: **1**.
5. Partial IP coverage without concrete advisories: **2**.
6. Observations match with requested source coverage: **0**.

Without `--reputation`, the existing routing-only behavior applies. An exit code of 0 is never a guarantee of continued Claude access.

## 5. Refresh, cache, and stopping

In watch mode, a daemon worker performs the exit/source checks while the main routing sampler continues. Slow or failed vendor requests do not pause the normal routing checks. There is at most one IP-intelligence job per process. Ctrl-C stops the process without waiting for a vendor to finish.

The default IP-check interval is **300 seconds after the previous job completes**. Change it with `--reputation-interval SECONDS`. Each check makes three new echo connections. Vendor results are cached **per source and IP for one hour**, in memory only; changing IPs still get separate reports. No unbounded persistent history is accumulated.

Cached reports retain their original `checked_at` and expose `cache.hit` and `cache.age_seconds_at_lookup`. The age is measured when the vendor cache was accessed; while a background refresh is running, the previous timestamped result is shown with `refresh_in_progress: true`. A fresh echo check is not a fresh vendor lookup. Provider errors are cached for five minutes. A 429 pauses that provider across **all queried IPs**, honoring `Retry-After` with a minimum five-minute pause and a one-hour fallback when absent; other providers remain available. Exhausted Scamalytics credits produce a provider cooldown. Expired entries are removed on subsequent lookups. Restarts discard cache/cooldowns, so repeated restarts can consume quota.

As documented on 2026-11-13, ipapi.is's anonymous budget is low and shared by callers behind the same public address. Even with caching, a rotating pool or repeated restarts may reach limits. Respect the returned quota state; do not retry aggressively or rotate IPs to defeat limits.

Network operations use an eight-second per-socket timeout. This is not a strict wall-clock deadline for an entire lookup; OS resolution and multiple request phases can extend the total duration. Source failure never triggers a direct or certificate-unverified retry.

## 6. Library API

```python
from claude_route_watch import request
from ip_reputation import collect_reputation

cache = {}  # One owner; no concurrent writes. Keep for the duration of the observer.
report = collect_reputation(
    proxy="http://127.0.0.1:7890",
    expected="YOUR FINAL NODE",
    read_connections=lambda: request("/connections"),
    cache=cache,
    previous_ips=None,
)
```

`collect_reputation` requires complete route attribution before querying providers. `probe_exit` in `exit_probe` is also callable separately.

For an explicitly supplied public IP, `lookup_reputation` in `ip_reputation` can query sources without claiming that the IP belongs to Claude. The caller owns that attribution:

```python
from ip_reputation import lookup_reputation

report = lookup_reputation(["1.1.1.1"], proxy="http://127.0.0.1:7890")
```

`lookup_reputation(..., credentials=mapping)` accepts an explicit credential mapping; otherwise it reads the current environment. `cache` is an optional in-memory mapping. Do not share one mapping between concurrent callers. No real keys belong in source code or saved examples.

## 7. Decisions and acceptance evidence

Adopt separate route evidence and provider-attributed IP intelligence. Reject an aggregate safety score, arbitrary country/ASN allowlists, and promises of account-ban detection. Keep the controller read-only, external queries opt-in, and missing evidence visible.

Stop short of IP-reputation conclusions if route attribution fails or provider fields are missing. Keep the corresponding source/result unknown instead of substituting an IP, bypassing TLS verification, silently downgrading authentication, or renormalizing missing scores.

Local verification on macOS (2026-11-13): three fresh echo connections were matched to the expected node and returned a consistent public IP. Anonymous ipapi.is returned location/ASN ownership; security flags stayed null. Missing Scamalytics/AbuseIPDB credentials were skipped without requests. A bounded watch repeatedly refreshed the echo probe while reusing the same timestamped anonymous result from cache. Setting a deliberately different expected node produced three mismatched samples, null IPs and an empty reputation result, without changing the proxy configuration. No personal IPs, node names, or live captures are included in this repository.

Synthetic tests cover source-address/port attribution, wrong/missing/duplicate chains, TLS and redirect refusal, rotating/partial probes, missing credentials, full vendor responses, plan placeholders, application/HTTP errors, secret-safe error reporting, cross-IP rate-limit cooldown, timestamped cache, source disagreement, and nonblocking watch behavior. Real authenticated vendor responses, a real quota exhaustion, actual destination-dependent rotation, long-running stability, notification display, and non-macOS live controllers remain unverified.
