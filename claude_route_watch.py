"""Read-only Claude routing scores for Mihomo / Clash Verge. Python 3.10+."""
import argparse
import collections
import http.client
import json
import math
import os
from pathlib import Path
import re
import shlex
import socket
import subprocess
import time


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
    args = parser.parse_args()
    if not math.isfinite(args.interval) or not math.isfinite(args.duration) or args.interval <= 0 or args.duration < 0:
        parser.error('interval must be positive and duration nonnegative; both must be finite')
    if args.test_notification:
        notify('Claude Route Watch: TEST', 'Test notification only. No routing or account incident detected.')
        print('Test notification submitted. Check Notification Center for actual delivery.')
        return 0
    if not args.expect or args.expect.upper() in ('DIRECT', 'REJECT', 'REJECT-DROP'):
        parser.error('--expect must name the expected final proxy node')
    last = None
    started = time.monotonic()
    while True:
        try:
            report = analyze(request('/configs', args.config, args.socket),
                             request('/connections', args.config, args.socket), args.expect)
        except (OSError, ValueError, KeyError, TypeError, AttributeError, http.client.HTTPException, RuntimeError):
            # Never print raw exceptions: they may contain credentials or local paths.
            report = {'scoring_version': 1, 'score': None, 'status': 'unknown',
                      'expected': args.expect, 'issues': ['Cannot read Mihomo runtime; monitoring unavailable']}
        issues = report['issues']
        fingerprint = (report['status'], report['score'], tuple(issues))
        if fingerprint != last:
            report['time'] = time.strftime('%Y-%m-%d %H:%M:%S%z')
            print(json.dumps(report, ensure_ascii=False), flush=True)
            recovered = last is not None and (bool(last[2]) or last[1] is None) and not issues and report['score'] is not None
            if args.notify and (issues or recovered or report['score'] is None):
                try:
                    notify('Claude routing warning' if issues else 'Claude routing status',
                           '; '.join(issues)[:600] if issues else report['status'])
                except (OSError, subprocess.TimeoutExpired, RuntimeError):
                    print('Notification delivery failed; see terminal report.', flush=True)
            last = fingerprint
        if not args.watch or (args.duration and time.monotonic() - started >= args.duration):
            return 2 if report['score'] is None else (1 if issues else 0)
        remaining = args.duration - (time.monotonic() - started) if args.duration else args.interval
        time.sleep(max(0, min(args.interval, remaining)))


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        pass
