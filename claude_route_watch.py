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
import sys
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
    node_changes = set()
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
                node_changes.add(f'{host}: {route}; expected endpoint {expected}')
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
    issues |= node_changes
    status = 'unknown' if score is None else ('warning' if issues else 'observed_ok')
    return {
        'scoring_version': 1, 'score': score, 'status': status, 'expected': expected,
        'scope': 'Mihomo-visible active Claude connections only',
        'observed_connections': total, 'components': components,
        'observed_endpoints': sorted(endpoints),
        'issues': sorted(issues),
        'node_changes': sorted(node_changes),
        'connections': [{'host': k[0], 'route': k[1], 'count': v} for k, v in sorted(summary.items())],
    }


def probe_node(report, expected):
    """Probe through the node Claude actually uses; None when that is not a single proxy node."""
    endpoints = report.get('observed_endpoints') or []
    if not report.get('observed_connections'):
        return expected  # Idle: nothing to attribute, so check the chosen node.
    if report.get('score') is None or len(endpoints) != 1 or endpoints[0].upper() == 'DIRECT':
        return None
    return endpoints[0]


def judge_exit(report, reputation, baseline, expected):
    """Exit-IP verdict. A renamed or switched node is only a record when the exit IP is unchanged."""
    endpoints = report.get('observed_endpoints') or []
    result = {'status': 'unchecked', 'baseline_ips': baseline, 'current_ips': [],
              'probed_node': (reputation or {}).get('probed_node')}
    if any(name.upper() == 'DIRECT' for name in endpoints):
        return dict(result, status='direct')
    if reputation is None:
        return result
    probe = reputation.get('probe') or {}
    if reputation.get('status') == 'pending':
        return dict(result, status='pending')
    if probe.get('status') != 'verified' or not probe.get('ips'):
        return dict(result, status='unknown')
    result['current_ips'] = probe['ips']
    if baseline is None:
        return dict(result, status='observed' if result['probed_node'] == expected else 'unconfirmed')
    return dict(result, status='matches' if sorted(probe['ips']) == sorted(baseline) else 'changed')


def notify(title, message):
    script = 'on run argv\ndisplay notification (item 2 of argv) with title (item 1 of argv)\nend run'
    result = subprocess.run(['osascript', '-e', script, title, message], capture_output=True, text=True, timeout=8)
    if result.returncode:
        raise RuntimeError('macOS notification command failed')


def main(argv=None, report_output=None):
    try:
        return _main(argv, report_output)
    except KeyboardInterrupt:
        return 0  # Ctrl-C is the documented way to stop; the console script must not print a traceback.


def _main(argv=None, report_output=None):
    argv = sys.argv[1:] if argv is None else argv
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--expect', help='Expected final proxy node name for route checks')
    mode.add_argument('--ip', action='store_true', help='Check this machine\'s public IP directly; no Clash required')
    mode.add_argument('--menu', action='store_true', help='Open the interactive terminal menu (default with no arguments)')
    parser.add_argument('--json', action='store_true', help='Print structured JSON for --ip (route flags already emit JSON)')
    parser.add_argument('--details', action='store_true', help='Expand source evidence for --ip instead of the compact summary')
    parser.add_argument('--config', help='Mihomo YAML config path, used only to read controller secret')
    parser.add_argument('--socket', help='Mihomo Unix socket path')
    parser.add_argument('--watch', action='store_true', help='Watch continuously; default: one snapshot')
    parser.add_argument('--notify', action='store_true', help='macOS notifications for warnings and recovery')
    parser.add_argument('--test-notification', action='store_true')
    parser.add_argument('--interval', type=float, default=2, help='Sampling interval in seconds')
    parser.add_argument('--duration', type=float, default=0, help='Stop after this many seconds; 0: continuous')
    parser.add_argument('--reputation', action='store_true', help='Opt in to routed exit probes and third-party IP intelligence')
    parser.add_argument('--proxy', help='Explicit loopback HTTP proxy URL; or CLAUDE_ROUTE_PROXY')
    parser.add_argument('--reputation-interval', type=float, default=300, help='Watch-mode exit check interval (seconds); vendor results cached for one hour')
    args = parser.parse_args(argv)
    if not math.isfinite(args.interval) or not math.isfinite(args.duration) or args.interval <= 0 or args.duration < 0:
        parser.error('interval must be positive and duration nonnegative; both must be finite')
    if not math.isfinite(args.reputation_interval) or args.reputation_interval <= 0:
        parser.error('reputation-interval must be positive and finite')
    if args.details and (not args.ip or args.json):
        parser.error('--details requires --ip without --json')
    if args.ip:
        if args.watch or args.reputation or args.notify or args.test_notification or args.proxy:
            parser.error('--ip is a direct one-shot check; do not combine with proxy, route watch or notification options')
        from terminal import check_ip, print_ip_report, print_ip_details, reputation_exit_code
        if not args.json:
            print('正在查询当前机器的公网 IP 与信誉来源……', flush=True)
        report = check_ip()
        if args.json:
            print(json.dumps(report, ensure_ascii=False))
        else:
            print_ip_details(report) if args.details else print_ip_report(report)
        return reputation_exit_code(report)
    if args.menu or not argv:
        if args.json or args.watch or args.reputation or args.test_notification:
            parser.error('Use the menu interactively, or choose --ip/--expect for unattended commands')
        from terminal import menu
        return menu(args.config, args.socket)
    args.proxy = args.proxy or os.environ.get('CLAUDE_ROUTE_PROXY')
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

    baseline = None  # First stable exit through the chosen node, this run only; never written to disk.
    probed = None

    def check_reputation(node):
        try:
            result = collect_reputation(args.proxy, node,
                                        lambda: request('/connections', args.config, args.socket),
                                        cache=cache, previous_ips=previous_ips)
        except Exception as error:
            # This is the background-job boundary: surface failure instead of losing the worker silently.
            result = {'status': 'unknown', 'ip_reports': [], 'error_type': type(error).__name__,
                      'warnings': ['IP intelligence job failed; evidence is unavailable']}
        result['probed_node'] = node
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
            node = probe_node(report, args.expect) if runtime_available else None
            if node != probed and worker is None:
                next_check = 0  # Claude moved to another node: check its exit now, not in five minutes.
            if runtime_available and node is None and worker is None:
                reputation = {'status': 'unknown', 'ip_reports': [], 'probed_node': None,
                              'warnings': ['No single Claude proxy route; exit cannot be attributed']}
                probed = None
            elif runtime_available and worker is None and time.monotonic() >= next_check:
                probed = node
                if args.watch:
                    # Slow vendor APIs must not pause the routing sampler. No service or disk state.
                    worker = threading.Thread(target=check_reputation, args=(node,), daemon=True)
                    worker.start()
                    if reputation is None or reputation.get('probed_node') != node:
                        # An older result describes another node's exit; never compare it to this one.
                        reputation = {'status': 'pending', 'ip_reports': [], 'warnings': [], 'probed_node': node}
                else:
                    check_reputation(node)
                    reputation = results.get_nowait()
                    if reputation.get('probe', {}).get('status') == 'verified':
                        previous_ips = reputation['probe']['ips']
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
            report['exit'] = judge_exit(report, reputation, baseline, args.expect)
            probe = reputation.get('probe') or {}
            if (baseline is None and reputation.get('probed_node') == args.expect and probe.get('status') == 'verified'
                    and probe.get('observed_stable') is True and len(probe.get('ips') or []) == 1):
                baseline = list(probe['ips'])  # Compared from the next check on; this one is the reference.
                report['exit']['baseline_ips'] = baseline
            if report['exit']['status'] in ('matches', 'pending'):
                # The user's rule: the exit is what matters; a different node with the same exit is a record.
                report['issues'] = [item for item in report['issues'] if item not in report.get('node_changes', [])]
                if not report['issues'] and report['score'] is not None:
                    report['status'] = 'observed_ok'
            elif report['exit']['status'] == 'changed':
                report['issues'] = report['issues'] + [
                    'Exit IP changed: baseline ' + ', '.join(baseline) + '; now ' + ', '.join(report['exit']['current_ips'])]
                report['status'] = 'warning'
        issues = report['issues']
        rep = report.get('reputation', {})
        fingerprint = (report['status'], report['score'], tuple(issues), json.dumps(rep, sort_keys=True))
        if fingerprint != last:
            report['time'] = time.strftime('%Y-%m-%d %H:%M:%S%z')
            if report_output is None:
                print(json.dumps(report, ensure_ascii=False), flush=True)
            else:
                report_output(report)
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
    raise SystemExit(main())
