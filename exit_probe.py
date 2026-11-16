"""HTTPS through an explicit loopback HTTP proxy, with Mihomo route evidence."""
import base64
from contextlib import contextmanager
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import http.client
import ipaddress
import json
import ssl
import time
from urllib.parse import unquote, urlsplit

PROBE_URL = 'https://api64.ipify.org/?format=json'


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


class FetchError(Exception):
    """Safe transport error: never retain response bodies, URLs, or credentials."""
    def __init__(self, reason, http_status=None, retry_after=None):
        super().__init__(reason)
        self.reason = reason
        self.http_status = http_status
        self.retry_after = retry_after


class RouteError(Exception):
    def __init__(self, evidence):
        super().__init__('Probe route could not be verified')
        self.evidence = evidence


def parse_proxy(proxy):
    try:
        value = urlsplit(proxy)
        host, port = value.hostname, value.port
        loopback = host == 'localhost' or (host and ipaddress.ip_address(host).is_loopback)
        if value.scheme != 'http' or not loopback or port is None or value.path not in ('', '/') or value.query or value.fragment:
            raise ValueError
        return value
    except (ValueError, TypeError):
        raise ValueError('Use an explicit loopback HTTP proxy URL, such as http://127.0.0.1:7890') from None


@contextmanager
def https_tunnel(url, proxy):
    target = urlsplit(url)
    if target.scheme != 'https' or not target.hostname or target.username or target.password or target.fragment:
        raise ValueError('HTTPS target without credentials required')
    local_proxy = parse_proxy(proxy)
    auth = {}
    if local_proxy.username is not None:
        credentials = unquote(local_proxy.username) + ':' + unquote(local_proxy.password or '')
        auth['Proxy-Authorization'] = 'Basic ' + base64.b64encode(credentials.encode()).decode()
    connection = http.client.HTTPSConnection(local_proxy.hostname, local_proxy.port,
                                             timeout=8, context=ssl.create_default_context())
    connection.set_tunnel(target.hostname, target.port or 443, headers=auth)
    try:
        connection.connect()
        yield connection, target
    finally:
        connection.close()


def retry_seconds(value):
    if not value:
        return None
    try:
        seconds = int(value)
    except (ValueError, TypeError):
        try:
            seconds = int((parsedate_to_datetime(value) - datetime.now(timezone.utc)).total_seconds())
        except (ValueError, TypeError, OverflowError):
            return None
    return max(0, seconds)


def fetch_json(url, proxy, *, payload=None, headers=None, observe=None):
    """No redirects, environment proxy fallback, or disabled TLS verification."""
    with https_tunnel(url, proxy) as (connection, target):
        evidence = observe(connection.sock.getsockname(), target.hostname) if observe else None
        if evidence is not None and evidence['status'] != 'verified':
            raise RouteError(evidence)
        request_headers = {'Accept': 'application/json', 'User-Agent': 'claude-route-watch'}
        request_headers.update(headers or {})
        body = json.dumps(payload).encode() if payload is not None else None
        if body is not None:
            request_headers['Content-Type'] = 'application/json'
        path = (target.path or '/') + ('?' + target.query if target.query else '')
        connection.request('POST' if body is not None else 'GET', path, body=body, headers=request_headers)
        response = connection.getresponse()
        if response.status != 200:
            raise FetchError('http_error', response.status, retry_seconds(response.getheader('Retry-After')))
        data = response.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise FetchError('response_too_large')
        result = json.loads(data)
        if not isinstance(result, dict):
            raise FetchError('invalid_json_object')
        return result, evidence


def verify_probe_route(snapshot, local_address, host, expected):
    """Correlate this socket, not another connection sharing an echo-service host."""
    address = ipaddress.ip_address(local_address[0])
    address = getattr(address, 'ipv4_mapped', None) or address
    matches = []
    for connection in snapshot['connections']:
        metadata = connection['metadata']
        if str(metadata.get('sourcePort')) != str(local_address[1]):
            continue
        try:
            source = ipaddress.ip_address(metadata.get('sourceIP', ''))
        except ValueError:
            continue
        source = getattr(source, 'ipv4_mapped', None) or source
        observed_host = metadata.get('host') or metadata.get('sniffHost') or ''
        if source == address and observed_host.lower().rstrip('.') == host.lower() and str(metadata.get('destinationPort')) == '443':
            matches.append(connection)
    if len(matches) != 1:
        return {'status': 'unknown', 'reason': 'probe_socket_not_uniquely_visible', 'matching_connections': len(matches)}
    connection = matches[0]
    chains = connection.get('chains', [])
    return {'status': ('verified' if chains[0] == expected else 'mismatch') if chains else 'unknown',
            'chain': list(reversed(chains)), 'rule': connection.get('rule'),
            'rule_payload': connection.get('rulePayload'),
            'reason': 'expected_node_matches' if chains and chains[0] == expected else 'missing_or_unexpected_endpoint'}


def probe_exit(proxy, expected, read_connections, samples=3):
    """Fresh CONNECT/TLS sessions; attribution must succeed before reading the echo."""
    parse_proxy(proxy)
    if samples < 2:
        raise ValueError('At least two samples are needed to describe observed stability')
    started = time.monotonic()
    observations = []
    for _ in range(samples):
        sample = {'checked_at': utc_now(), 'status': 'unknown', 'ip': None}
        try:
            def observe(local, host):
                return verify_probe_route(read_connections(), local, host, expected)
            data, evidence = fetch_json(PROBE_URL, proxy, observe=observe,
                                        headers={'Cache-Control': 'no-cache'})
            if not isinstance(data.get('ip'), str):
                raise ValueError('No echo IP')
            ip = ipaddress.ip_address(data['ip'])
            if not ip.is_global or ip.is_multicast:
                raise ValueError('Echo did not return a global public IP')
            sample.update(status='verified', ip=str(ip), route=evidence)
        except RouteError as error:
            sample.update(reason='route_unverified', route=error.evidence)
        except FetchError as error:
            sample.update(reason=error.reason, http_status=error.http_status)
        except (OSError, ValueError, KeyError, TypeError, AttributeError, RuntimeError, http.client.HTTPException) as error:
            sample.update(reason='probe_or_controller_failed', error_type=type(error).__name__)
        observations.append(sample)
    ips = sorted({sample['ip'] for sample in observations if sample['status'] == 'verified'})
    verified = all(sample['status'] == 'verified' for sample in observations)
    return {'status': 'verified' if verified else 'unknown', 'service': PROBE_URL,
            'checked_at': utc_now(), 'sample_count': samples,
            'elapsed_seconds': round(time.monotonic() - started, 3),
            'ips': ips, 'observed_stable': len(ips) == 1 if verified else None,
            'samples': observations,
            'scope': 'Echo-service IP through the expected Mihomo node; not Anthropic-side IP proof'}
