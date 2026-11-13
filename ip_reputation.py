"""Source-attributed IP intelligence. Vendor scores never alter the routing score."""
from copy import deepcopy
import http.client
import ipaddress
import math
import os
import time
from urllib.parse import quote, urlencode

from exit_probe import FetchError, fetch_json, utc_now

DOCS = {
    'ipapi.is': 'https://ipapi.is/developers.html',
    'scamalytics': 'https://docs.scamalytics.com/ip-fraud-risk-api/v3/',
    'abuseipdb': 'https://docs.abuseipdb.com/',
}


def text(value):
    if not isinstance(value, str) or not value.strip() or value == '-' or value.startswith('PREMIUM FIELD'):
        return None
    return value


def boolean(value):
    return value if isinstance(value, bool) else None


def number(value):
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) else None


def score_100(value):
    value = number(value)
    if value is not None and not 0 <= value <= 100:
        raise FetchError('invalid_vendor_score')
    return value


def country_code(value):
    value = text(value)
    return value.upper() if value and len(value) == 2 and value.isascii() and value.isalpha() else None


def public_ip(value):
    if not isinstance(value, str):
        raise ValueError('A public IPv4 or IPv6 string is required')
    address = ipaddress.ip_address(value)
    if not address.is_global or address.is_multicast:
        raise ValueError('A public IPv4 or IPv6 address is required')
    return str(address)


def base_report(provider, ip):
    return {'provider': provider, 'queried_ip': ip, 'checked_at': utc_now(),
            'source': DOCS[provider], 'status': 'unknown',
            'geo': {'country_code': None, 'country_name': None, 'region': None, 'city': None},
            'network': {}, 'flags': {}, 'scores': [], 'details': {}, 'missing_fields': []}


def check_returned_ip(actual, expected):
    if not isinstance(actual, str) or str(ipaddress.ip_address(actual)) != expected:
        raise FetchError('returned_ip_mismatch')


def normalize_ipapi(data, ip):
    if data.get('error') or data.get('error_code'):
        raise FetchError('provider_error')
    check_returned_ip(data.get('ip'), ip)
    report = base_report('ipapi.is', ip)
    company = data.get('company')
    asn = data.get('asn')
    location = data.get('location') or {}
    report['geo'] = {
        'country_code': country_code(location.get('country_code')),
        'country_name': text(location.get('country') or data.get('country')),
        'region': text(location.get('state') or data.get('region')),
        'city': text(location.get('city') or data.get('city')),
    }
    report['network'] = {
        'asn': number(asn.get('asn')) if isinstance(asn, dict) else None,
        'asn_label': text(asn) if isinstance(asn, str) else None,
        'asn_organization': text(asn.get('org')) if isinstance(asn, dict) else None,
        'asn_type': text(asn.get('type')) if isinstance(asn, dict) else None,
        'asn_registration_country': country_code(asn.get('country')) if isinstance(asn, dict) else None,
        'company': text(company.get('name')) if isinstance(company, dict) else text(company),
        'company_type': text(company.get('type')) if isinstance(company, dict) else None,
        'prefix': text(asn.get('route')) if isinstance(asn, dict) else None,
        'rir': text(data.get('rir')),
    }
    report['flags'] = {name: boolean(data.get('is_' + name)) for name in
                       ('datacenter', 'vpn', 'proxy', 'tor', 'abuser', 'mobile', 'satellite', 'anycast')}
    report['details']['access'] = 'anonymous' if data.get('docs') else 'keyed_or_unspecified'
    report['scores'] = [
        {'name': 'company.abuser_score', 'value': text(company.get('abuser_score')) if isinstance(company, dict) else None,
         'scope': 'WHOIS company network', 'meaning': 'Vendor-reported share of network addresses seen in abuse; not a per-IP fraud or ban probability'},
        {'name': 'asn.abuser_score', 'value': text(asn.get('abuser_score')) if isinstance(asn, dict) else None,
         'scope': 'ASN IPv4 routes', 'meaning': 'Vendor-reported network abuse fraction; not a per-IP fraud or ban probability'},
    ]
    report['missing_fields'] = ['flags.' + name for name in ('datacenter', 'vpn', 'proxy', 'tor', 'abuser')
                                if report['flags'][name] is None]
    if not report['geo']['country_code']:
        report['missing_fields'].append('geo.country_code')
    report['status'] = 'partial' if report['missing_fields'] else 'ok'
    return report


def normalize_scamalytics(data, ip):
    value = data['scamalytics']
    if value.get('status') != 'ok':
        exhausted = (value.get('credits') or {}).get('remaining') == 0
        raise FetchError('credits_exhausted' if exhausted else 'provider_error', retry_after=3600 if exhausted else None)
    check_returned_ip(value.get('ip'), ip)
    if value.get('mode') != 'live':
        raise FetchError('non_live_vendor_response')
    report = base_report('scamalytics', ip)
    external = data.get('external_datasources') or {}
    geo = external.get('maxmind_geolite2') or {}
    proxy = value.get('scamalytics_proxy') or {}
    report['geo'] = {'country_code': country_code(geo.get('ip_country_code')), 'country_name': None,
                     'region': text(geo.get('ip_state_name')), 'city': text(geo.get('ip_city'))}
    report['network'] = {'asn': text(geo.get('asn')) or number(geo.get('asn')),
                         'isp': text(value.get('scamalytics_isp')), 'organization': text(value.get('scamalytics_org'))}
    report['flags'] = {'datacenter': boolean(proxy.get('is_datacenter')), 'vpn': boolean(proxy.get('is_vpn')),
                       'residential_proxy': boolean(proxy.get('is_resproxy')),
                       'icloud_private_relay': boolean(proxy.get('is_apple_icloud_private_relay')),
                       'external_blacklist': boolean(value.get('is_blacklisted_external'))}
    ip_score = score_100(value.get('scamalytics_score'))
    report['scores'] = [
        {'name': 'scamalytics_score', 'value': ip_score, 'scale': [0, 100], 'higher_means': 'more vendor-assessed fraud risk',
         'scope': 'IP', 'meaning': 'Scamalytics proprietary fraud score, not Claude account-ban probability'},
        {'name': 'scamalytics_isp_score', 'value': score_100(value.get('scamalytics_isp_score')), 'scale': [0, 100],
         'scope': 'ISP network', 'meaning': 'Vendor assessment of the network as a whole, not this account'},
    ]
    report['details'] = {'vendor_risk': text(value.get('scamalytics_risk')),
                         'vendor_isp_risk': text(value.get('scamalytics_isp_risk')),
                         'mode': value.get('mode'), 'geolocation_source': 'MaxMind GeoLite2 via Scamalytics',
                         'credits_remaining': number((value.get('credits') or {}).get('remaining'))}
    # Preserve the source of each blacklist/secondary flag; do not count feeds as independent votes.
    report['details']['external_evidence'] = {
        source: {field: boolean((external.get(source) or {}).get(field)) for field in fields}
        for source, fields in {
            'firehol': ('ip_blacklisted_30', 'ip_blacklisted_1day'),
            'ipsum': ('ip_blacklisted',), 'spamhaus_drop': ('ip_blacklisted',),
            'x4bnet': ('is_vpn', 'is_datacenter', 'is_tor'),
        }.items()
    }
    report['missing_fields'] = ['flags.' + name for name in ('datacenter', 'vpn', 'residential_proxy') if report['flags'][name] is None]
    if ip_score is None:
        report['missing_fields'].append('scores.scamalytics_score')
    if report['details']['vendor_risk'] is None:
        report['missing_fields'].append('details.vendor_risk')
    if not report['geo']['country_code']:
        report['missing_fields'].append('geo.country_code')
    report['status'] = 'partial' if report['missing_fields'] else 'ok'
    return report


def normalize_abuseipdb(data, ip):
    if data.get('errors'):
        raise FetchError('provider_error')
    value = data['data']
    check_returned_ip(value.get('ipAddress'), ip)
    report = base_report('abuseipdb', ip)
    confidence = score_100(value.get('abuseConfidenceScore'))
    report['geo'].update(country_code=country_code(value.get('countryCode')), country_name=text(value.get('countryName')))
    report['network'] = {'isp': text(value.get('isp')), 'usage_type': text(value.get('usageType')), 'domain': text(value.get('domain'))}
    report['flags'] = {'tor': boolean(value.get('isTor')), 'whitelisted': boolean(value.get('isWhitelisted'))}
    report['scores'] = [{'name': 'abuseConfidenceScore', 'value': confidence, 'scale': [0, 100],
                         'higher_means': 'more confidence in reported abuse', 'scope': 'IP',
                         'meaning': 'AbuseIPDB report-based abuse confidence; zero does not prove no abuse or no Claude risk'}]
    report['details'] = {'report_window_days': 90, 'total_reports': number(value.get('totalReports')),
                         'distinct_reporters': number(value.get('numDistinctUsers')),
                         'last_reported_at': text(value.get('lastReportedAt')),
                         'geolocation_source': 'IPinfo via AbuseIPDB'}
    report['missing_fields'] = [] if confidence is not None else ['scores.abuseConfidenceScore']
    if report['details']['total_reports'] is None:
        report['missing_fields'].append('details.total_reports')
    if not report['geo']['country_code']:
        report['missing_fields'].append('geo.country_code')
    report['status'] = 'partial' if report['missing_fields'] else 'ok'
    return report


def query_provider(provider, ip, proxy, credentials):
    if provider == 'ipapi.is':
        key = credentials.get('IPAPI_IS_KEY')
        if key:
            data, _ = fetch_json('https://api.ipapi.is/', proxy, payload={'q': ip, 'key': key})
        else:
            data, _ = fetch_json('https://api.ipapi.is/?' + urlencode({'q': ip}), proxy)
        return normalize_ipapi(data, ip)
    if provider == 'scamalytics':
        region = credentials.get('SCAMALYTICS_REGION', 'us')
        if region not in ('us', 'eu'):
            raise FetchError('invalid_scamalytics_region')
        host = 'api11.scamalytics.com' if region == 'us' else 'api12.scamalytics.com'
        query = urlencode({'ip': ip, 'key': credentials['SCAMALYTICS_KEY']})
        username = quote(credentials['SCAMALYTICS_USERNAME'], safe='')
        data, _ = fetch_json(f'https://{host}/v3/{username}?{query}', proxy)
        return normalize_scamalytics(data, ip)
    query = urlencode({'ipAddress': ip, 'maxAgeInDays': 90})
    data, _ = fetch_json('https://api.abuseipdb.com/api/v2/check?' + query, proxy,
                          headers={'Key': credentials['ABUSEIPDB_KEY']})
    return normalize_abuseipdb(data, ip)


def lookup_provider(provider, ip, proxy, credentials, cache):
    required = {'ipapi.is': (), 'scamalytics': ('SCAMALYTICS_USERNAME', 'SCAMALYTICS_KEY'), 'abuseipdb': ('ABUSEIPDB_KEY',)}[provider]
    missing = [name for name in required if not credentials.get(name)]
    if missing:
        report = base_report(provider, ip)
        report.update(status='skipped', reason='missing_credentials', required_environment=missing)
        return report
    now = time.monotonic()
    item = cache.get((provider, ip))
    if item and now < item['expires']:
        report = deepcopy(item['report'])
        report['cache'] = {'hit': True, 'age_seconds_at_lookup': round(now - item['stored'], 1)}
        return report
    cooldown = cache.get((provider, None))
    if cooldown and now < cooldown:
        report = base_report(provider, ip)
        report.update(status='rate_limited', reason='provider_cooldown', retry_after_seconds=math.ceil(cooldown - now))
        return report
    try:
        report = query_provider(provider, ip, proxy, credentials)
    except FetchError as error:
        report = base_report(provider, ip)
        status = 'rate_limited' if error.http_status == 429 or error.reason == 'credits_exhausted' else 'error'
        report.update(status=status, reason=error.reason, http_status=error.http_status,
                      retry_after_seconds=error.retry_after)
        if status == 'rate_limited':
            cache[(provider, None)] = time.monotonic() + max(300, error.retry_after or 3600)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, http.client.HTTPException) as error:
        report = base_report(provider, ip)
        report.update(status='error', reason='network_or_invalid_response', error_type=type(error).__name__)
    ttl = 3600 if report['status'] in ('ok', 'partial') else 300
    stored = time.monotonic()
    cache[(provider, ip)] = {'report': deepcopy(report), 'stored': stored, 'expires': stored + ttl}
    report['cache'] = {'hit': False, 'age_seconds_at_lookup': 0}
    return report


def summarize_ip(ip, providers):
    countries = {report['provider']: report['geo']['country_code'] for report in providers if report['geo']['country_code']}
    comparison = ('insufficient_data' if len(countries) < 2 else
                  ('agreement' if len(set(countries.values())) == 1 else 'disagreement'))
    disagreements = []
    for flag in ('datacenter', 'vpn', 'proxy', 'tor', 'residential_proxy'):
        evidence = {report['provider']: report['flags'][flag] for report in providers if report['flags'].get(flag) is not None}
        if len(set(evidence.values())) > 1:
            disagreements.append({'field': flag, 'values': evidence})
    advisories = []
    for report in providers:
        source = report['provider']
        for flag in ('abuser', 'external_blacklist'):
            if report['flags'].get(flag) is True:
                advisories.append(f'{source} reports {flag}=true for {ip}; inspect source evidence')
        risk = report['details'].get('vendor_risk')
        if risk in ('medium', 'high', 'very high'):
            metric = next((item['value'] for item in report['scores'] if item['name'] == 'scamalytics_score'), None)
            advisories.append(f'{source} reports vendor fraud score={metric}, risk={risk} for {ip}; not account-ban risk')
        if source == 'abuseipdb':
            confidence = next((item['value'] for item in report['scores'] if item['name'] == 'abuseConfidenceScore'), None)
            if confidence is not None and confidence > 0:
                advisories.append(f'AbuseIPDB abuseConfidenceScore={confidence} for {ip}; inspect report age and count')
    if comparison == 'disagreement':
        evidence = ', '.join(f'{source}={value}' for source, value in sorted(countries.items()))
        advisories.append(f'Providers disagree about country for {ip}: {evidence}')
    for disagreement in disagreements:
        evidence = ', '.join(f'{source}={value}' for source, value in sorted(disagreement['values'].items()))
        advisories.append(f'Providers disagree about {disagreement["field"]} for {ip}: {evidence}')
    return {'ip': ip, 'providers': providers,
            'country_comparison': {'status': comparison, 'values': countries,
                                   'note': 'Country names are not guessed into codes; sources may share upstream data'},
            'flag_disagreements': disagreements, 'advisories': advisories,
            'coverage': {report['provider']: report['status'] for report in providers}}


def lookup_reputation(ips, proxy, *, cache=None, credentials=None):
    """Query each public IP explicitly. cache is optional, in-memory, provider-attributed."""
    cache = {} if cache is None else cache
    credentials = os.environ if credentials is None else credentials
    now = time.monotonic()
    for key, value in list(cache.items()):
        if now >= (value if key[1] is None else value['expires']):
            del cache[key]
    addresses = sorted({public_ip(ip) for ip in ips})
    reports = []
    for ip in addresses:
        providers = [lookup_provider(provider, ip, proxy, credentials, cache) for provider in DOCS]
        reports.append(summarize_ip(ip, providers))
    statuses = [provider['status'] for report in reports for provider in report['providers']]
    status = ('complete' if statuses and all(value == 'ok' for value in statuses) else
              ('partial' if any(value in ('ok', 'partial') for value in statuses) else 'unknown'))
    return {'status': status, 'checked_at': utc_now(), 'ip_reports': reports,
            'warnings': [item for report in reports for item in report['advisories']],
            'interpretation': 'Vendor evidence only: no aggregate IP safety score or Claude-ban probability'}


def collect_reputation(proxy, expected, read_connections, *, cache=None, previous_ips=None):
    from exit_probe import probe_exit
    probe = probe_exit(proxy, expected, read_connections)
    if probe['status'] != 'verified':
        return {'status': 'unknown', 'checked_at': utc_now(), 'probe': probe,
                'ip_reports': [], 'change_since_previous_check': None,
                'warnings': ['Exit probe is not fully route-verified; reputation lookup was not performed']}
    result = lookup_reputation(probe['ips'], proxy, cache=cache)
    result['probe'] = probe
    result['change_since_previous_check'] = {
        'previous_ips': previous_ips, 'current_ips': probe['ips'],
        'changed': sorted(previous_ips) != probe['ips'] if previous_ips is not None else None,
    }
    if not probe['observed_stable']:
        result['warnings'].append('Exit IP changed across fresh probe connections; inspect all observed IPs')
    if result['change_since_previous_check']['changed']:
        result['warnings'].append('Observed exit IP set changed since the previous verified check')
    return result
