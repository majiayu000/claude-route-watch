"""Read-only Claude routing scores for Mihomo / Clash Verge. Python 3.10+."""
import argparse
import collections
import http.client
import json
import math
import os
from pathlib import Path
import queue
import re
import shlex
import socket
import subprocess
import threading
import time

from exit_probe import parse_proxy
from ip_reputation import collect_reputation


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__('localhost', timeout=4)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def request(endpoint, config_path=None, socket_path=None):
    base = Path.home() / 'Library/Application Support/io.github.clash-verge-rev.clash-verge-rev'
    config_file = Path(config_path) if config_path else base / 'clash-verge.yaml'
    config = config_file.read_text() if config_file.exists() else ''
    match = re.search(r'^secret:[ \t]*([^\n]*)$', config, re.M)
    words = shlex.split(match.group(1), comments=True) if match else []
    token = os.environ.get('MIHOMO_SECRET', words[0] if words else '')
    paths = (socket_path,) if socket_path else ('/var/tmp/verge/verge-mihomo.sock', '/tmp/verge/verge-mihomo.sock')
    path = next((p for p in paths if Path(p).is_socket()), None)
    if path is None:
        raise RuntimeError('No Mihomo Unix socket found')
    client = UnixHTTP(path)
    try:
        client.request('GET', endpoint, headers={'Authorization': 'Bearer ' + token})
        response = client.getresponse()
        if response.status != 200:
            raise RuntimeError(f'Mihomo API {endpoint}: HTTP {response.status}')
        return json.loads(response.read())
    finally:
        client.close()


def belongs_to_claude(metadata):
    process = metadata.get('process', '').lower()
    path = metadata.get('processPath', '').lower()
    host = (metadata.get('host') or metadata.get('sniffHost') or '').lower().rstrip('.')
    return (process in ('claude', 'claude.exe') or process.startswith('claude helper')
            or '/.local/share/claude/versions/' in path or '/claude.app/' in path
            or any(host == d or host.endswith('.' + d) for d in
                   ('anthropic.com', 'claude.ai', 'claude.com', 'claudeusercontent.com', 'claudemcpcontent.com')))


def analyze(config, connections, expected):
    """Score one snapshot. No I/O or ban prediction; None means insufficient evidence."""
    if not isinstance(expected, str) or not expected or expected.upper() in ('DIRECT', 'REJECT', 'REJECT-DROP'):
        raise ValueError('expected must name a proxy endpoint, not a direct/reject policy')
    issues = set()
    tun = config.get('tun', {}).get('enable') is True
    if not tun:
        issues.add('TUN is not enabled: traffic outside the system proxy may be invisible')
    summary = collections.Counter()
    endpoints = set()
    matched = total = 0
    incomplete = direct = False
    for connection in connections['connections']:
        metadata = connection['metadata']
        if not belongs_to_claude(metadata):
            continue
        total += 1
        chains = connection.get('chains', [])
        host = metadata.get('host') or metadata.get('sniffHost') or metadata.get('destinationIP') or 'unknown target'
        route = ' -> '.join(reversed(chains)) or 'unknown route'
        summary[(host, route)] += 1
        if not chains:
            incomplete = True
            issues.add(f'{host}: missing proxy chain')
        else:
            # Mihomo chains[0] is the endpoint; the last entry is the outer group.
            endpoint = chains[0]
            endpoints.add(endpoint)
            direct = direct or endpoint.upper() == 'DIRECT'
            matched += endpoint == expected
            if endpoint != expected:
                issues.add(f'{host}: {route}; expected endpoint {expected}')
    components = {
        'route_match': round(60 * matched / total, 1) if total and not incomplete else None,
        'endpoint_consistency': (20 if len(endpoints) == 1 else 0) if total and not incomplete else None,
        'tun_coverage': 20 if tun else 0,
    }
    score = None
    if direct:
        score = 0  # A known direct connection overrides uncertainty elsewhere.
    elif total and not incomplete:
        score = round(sum(components.values()), 1)
        if matched != total:
            score = min(score, 39)  # Normal connections must not dilute a wrong exit.
    status = 'unknown' if score is None else ('warning' if issues else 'observed_ok')
    return {
        'scoring_version': 1, 'score': score, 'status': status, 'expected': expected,
        'scope': 'Mihomo-visible active Claude connections only',
        'observed_connections': total, 'components': components,
        'observed_endpoints': sorted(endpoints),
        'issues': sorted(issues),
        'connections': [{'host': k[0], 'route': k[1], 'count': v} for k, v in sorted(summary.items())],
    }


def notify(title, message):
    script = 'on run argv\ndisplay notification (item 2 of argv) with title (item 1 of argv)\nend run'
    result = subprocess.run(['osascript', '-e', script, title, message], capture_output=True, text=True, timeout=8)
    if result.returncode:
        raise RuntimeError('macOS notification command failed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expect', help='Required: expected final proxy node name (no default)')
    parser.add_argument('--config', help='Mihomo YAML config path, used only to read controller secret')
    parser.add_argument('--socket', help='Mihomo Unix socket path')
    parser.add_argument('--watch', action='store_true', help='Watch continuously; default: one snapshot')
    parser.add_argument('--notify', action='store_true', help='macOS notifications for warnings and recovery')
    parser.add_argument('--test-notification', action='store_true')
    parser.add_argument('--interval', type=float, default=2, help='Sampling interval in seconds')
    parser.add_argument('--duration', type=float, default=0, help='Stop after this many seconds; 0: continuous')
    parser.add_argument('--reputation', action='store_true', help='Opt in to routed exit probes and third-party IP intelligence')
    parser.add_argument('--proxy', default=os.environ.get('CLAUDE_ROUTE_PROXY'), help='Explicit loopback HTTP proxy URL; or CLAUDE_ROUTE_PROXY')
    parser.add_argument('--reputation-interval', type=float, default=300, help='Watch-mode exit check interval (seconds); vendor results cached for one hour')
    args = parser.parse_args()
    if not math.isfinite(args.interval) or not math.isfinite(args.duration) or args.interval <= 0 or args.duration < 0:
        parser.error('interval must be positive and duration nonnegative; both must be finite')
    if not math.isfinite(args.reputation_interval) or args.reputation_interval <= 0:
        parser.error('reputation-interval must be positive and finite')
    if args.test_notification:
        notify('Claude Route Watch: TEST', 'Test notification only. No routing or account incident detected.')
        print('Test notification submitted. Check Notification Center for actual delivery.')
        return 0
    if not args.expect or args.expect.upper() in ('DIRECT', 'REJECT', 'REJECT-DROP'):
        parser.error('--expect must name the expected final proxy node')
    if args.reputation:
        try:
            parse_proxy(args.proxy)
        except ValueError as error:
            parser.error(str(error))
    last = None
    last_notice = None
    reputation = None
    cache = {}
    previous_ips = None
    worker = None
    results = queue.SimpleQueue()
    next_check = 0
    started = time.monotonic()

    def check_reputation():
        try:
            result = collect_reputation(args.proxy, args.expect,
                                        lambda: request('/connections', args.config, args.socket),
                                        cache=cache, previous_ips=previous_ips)
        except Exception as error:
            # This is the background-job boundary: surface failure instead of losing the worker silently.
            result = {'status': 'unknown', 'ip_reports': [], 'error_type': type(error).__name__,
                      'warnings': ['IP intelligence job failed; evidence is unavailable']}
        results.put(result)

    while True:
        runtime_available = True
        try:
            report = analyze(request('/configs', args.config, args.socket),
                             request('/connections', args.config, args.socket), args.expect)
        except (OSError, ValueError, KeyError, TypeError, AttributeError, http.client.HTTPException, RuntimeError):
            # Never print raw exceptions: they may contain credentials or local paths.
            report = {'scoring_version': 1, 'score': None, 'status': 'unknown',
                      'expected': args.expect, 'issues': ['Cannot read Mihomo runtime; monitoring unavailable']}
            runtime_available = False
        if args.reputation:
            try:
                reputation = results.get_nowait()
                worker = None
                next_check = time.monotonic() + args.reputation_interval
                if reputation.get('probe', {}).get('status') == 'verified':
                    previous_ips = reputation['probe']['ips']
            except queue.Empty:
                pass
            if runtime_available and worker is None and time.monotonic() >= next_check:
                if args.watch:
                    # Slow vendor APIs must not pause the routing sampler. No service or disk state.
                    worker = threading.Thread(target=check_reputation, daemon=True)
                    worker.start()
                    if reputation is None:
                        reputation = {'status': 'pending', 'ip_reports': [], 'warnings': []}
                else:
                    check_reputation()
                    reputation = results.get_nowait()
            if reputation is None:
                reputation = {'status': 'unknown', 'ip_reports': [],
                              'warnings': ['Controller unavailable; exit was not probed']}
            # Keep lookup evidence timestamped. A failed current controller never becomes a green report.
            report['reputation'] = dict(reputation)
            report['reputation']['claude_node_comparison'] = (
                'no_active_claude_evidence' if not report.get('observed_connections') else
                ('same_expected_node_observed_not_same_ip_proof' if report.get('observed_endpoints') == [args.expect]
                 else 'claude_node_mismatch_or_incomplete'))
            report['reputation']['refresh_in_progress'] = worker is not None
        issues = report['issues']
        rep = report.get('reputation', {})
        fingerprint = (report['status'], report['score'], tuple(issues), json.dumps(rep, sort_keys=True))
        if fingerprint != last:
            report['time'] = time.strftime('%Y-%m-%d %H:%M:%S%z')
            print(json.dumps(report, ensure_ascii=False), flush=True)
            notices = issues + rep.get('warnings', [])
            unknown = report['score'] is None or rep.get('status') in ('unknown', 'partial')
            notice = (tuple(notices), unknown)
            recovered = last_notice is not None and (bool(last_notice[0]) or last_notice[1]) and not notices and not unknown
            if args.notify and notice != last_notice and (notices or recovered or unknown):
                try:
                    notify('Claude network observation', '; '.join(notices)[:600] if notices else
                           ('Incomplete evidence: inspect terminal report' if unknown else 'Observation recovered'))
                except (OSError, subprocess.TimeoutExpired, RuntimeError):
                    print('Notification delivery failed; see terminal report.', flush=True)
            last = fingerprint
            last_notice = notice
        if not args.watch or (args.duration and time.monotonic() - started >= args.duration):
            if report['score'] is None:
                return 2
            if issues:
                return 1
            if rep.get('status') in ('unknown', 'pending'):
                return 2
            if rep.get('warnings'):
                return 1
            return 2 if rep.get('status') == 'partial' else 0
        remaining = args.duration - (time.monotonic() - started) if args.duration else args.interval
        time.sleep(max(0, min(args.interval, remaining)))


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        pass
