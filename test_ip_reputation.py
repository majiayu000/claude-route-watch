from copy import deepcopy
import json
import unittest
from unittest.mock import patch

from exit_probe import FetchError
from ip_reputation import (collect_reputation, lookup_provider, lookup_reputation, normalize_abuseipdb,
                           normalize_ipapi, normalize_scamalytics, public_ip, summarize_ip)

IP = '1.1.1.1'
PROXY = 'http://127.0.0.1:7890'


def ipapi():
    return {'ip': IP, 'company': {'name': 'Example ISP', 'type': 'isp', 'abuser_score': '0.0123 (Elevated)'},
            'asn': {'asn': 12345, 'org': 'Example ASN', 'type': 'isp', 'country': 'de', 'abuser_score': '0.01 (Low)'},
            'location': {'country_code': 'DE', 'country': 'Germany', 'city': 'Berlin'},
            'is_datacenter': False, 'is_vpn': False, 'is_proxy': False, 'is_tor': False, 'is_abuser': False}


def scam():
    return {'scamalytics': {'status': 'ok', 'mode': 'live', 'ip': IP, 'scamalytics_score': 87,
                           'scamalytics_risk': 'high', 'scamalytics_isp_score': 72,
                           'scamalytics_org': 'PREMIUM FIELD - upgrade to view',
                           'scamalytics_proxy': {'is_datacenter': True, 'is_vpn': False, 'is_resproxy': False},
                           'is_blacklisted_external': True, 'credits': {'remaining': 50}},
            'external_datasources': {'maxmind_geolite2': {'ip_country_code': 'US', 'asn': '12345'},
                                    'spamhaus_drop': {'ip_blacklisted': True}}}


def abuse():
    return {'data': {'ipAddress': IP, 'abuseConfidenceScore': 0, 'countryCode': 'DE', 'totalReports': 0,
                     'numDistinctUsers': 0, 'lastReportedAt': None, 'isWhitelisted': None, 'isTor': False}}


class Evidence(unittest.TestCase):
    def test_anonymous_ipapi_has_unknown_security_flags(self):
        report = normalize_ipapi({'ip': IP, 'company': 'Example ISP', 'asn': 'AS12345 Example',
                                  'country': 'Germany', 'docs': 'https://ipapi.is/free-tier.html'}, IP)
        self.assertEqual(report['status'], 'partial')
        self.assertIsNone(report['flags']['vpn'])
        self.assertIsNone(report['flags']['abuser'])
        self.assertEqual(report['geo']['country_name'], 'Germany')
        self.assertIsNone(report['geo']['country_code'])
        self.assertEqual(report['network']['asn_label'], 'AS12345 Example')

    def test_network_scores_are_not_ip_scores_and_false_is_not_missing(self):
        report = normalize_ipapi(ipapi(), IP)
        self.assertEqual(report['status'], 'ok')
        self.assertIs(report['flags']['vpn'], False)
        self.assertEqual(report['scores'][0]['value'], '0.0123 (Elevated)')
        self.assertEqual(report['scores'][0]['scope'], 'WHOIS company network')
        self.assertEqual(report['geo']['country_code'], 'DE')

    def test_wrong_types_missing_and_premium_placeholders_remain_unknown(self):
        payload = ipapi()
        payload['is_vpn'] = 'false'
        self.assertIsNone(normalize_ipapi(payload, IP)['flags']['vpn'])
        report = normalize_scamalytics(scam(), IP)
        self.assertIsNone(report['network']['organization'])
        self.assertEqual(report['scores'][0]['value'], 87)
        self.assertEqual(report['details']['external_evidence']['spamhaus_drop']['ip_blacklisted'], True)

    def test_zero_abuse_score_and_no_reports_are_preserved(self):
        report = normalize_abuseipdb(abuse(), IP)
        self.assertEqual(report['status'], 'ok')
        self.assertEqual(report['scores'][0]['value'], 0)
        self.assertEqual(report['details']['total_reports'], 0)
        self.assertIsNone(report['flags']['whitelisted'])
        self.assertIsNone(report['details']['last_reported_at'])

    def test_non_live_or_wrong_ip_is_rejected(self):
        payload = scam()
        payload['scamalytics']['mode'] = 'test'
        with self.assertRaises(FetchError):
            normalize_scamalytics(payload, IP)
        with self.assertRaises(FetchError):
            normalize_ipapi(ipapi(), '8.8.8.8')

    def test_invalid_score_ranges_and_missing_risk_label(self):
        for field in ('scamalytics_score', 'scamalytics_isp_score'):
            payload = scam()
            payload['scamalytics'][field] = 101
            with self.assertRaises(FetchError):
                normalize_scamalytics(payload, IP)
        payload = scam()
        del payload['scamalytics']['scamalytics_risk']
        self.assertEqual(normalize_scamalytics(payload, IP)['status'], 'partial')

    def test_country_and_flag_disagreement_keeps_each_source(self):
        providers = [normalize_ipapi(ipapi(), IP), normalize_scamalytics(scam(), IP)]
        report = summarize_ip(IP, providers)
        self.assertEqual(report['country_comparison']['status'], 'disagreement')
        self.assertEqual(report['country_comparison']['values'], {'ipapi.is': 'DE', 'scamalytics': 'US'})
        self.assertEqual(report['flag_disagreements'][0]['field'], 'datacenter')
        self.assertTrue(report['advisories'])
        self.assertNotIn('score', report)

    def test_one_country_is_not_cross_validation_and_datacenter_is_not_rejection(self):
        payload = ipapi()
        payload['is_datacenter'] = True
        report = summarize_ip(IP, [normalize_ipapi(payload, IP)])
        self.assertEqual(report['country_comparison']['status'], 'insufficient_data')
        self.assertEqual(report['advisories'], [])

    def test_public_ip_boundary_rejects_private_reserved_and_multicast(self):
        for value in ('127.0.0.1', '192.0.2.1', '224.0.0.1', 'not-an-ip', 123):
            with self.assertRaises(ValueError):
                public_ip(value)
        self.assertEqual(public_ip('2606:4700:4700::1111'), '2606:4700:4700::1111')


class Queries(unittest.TestCase):
    def test_missing_keys_skip_paid_queries_and_remain_partial(self):
        with patch('ip_reputation.fetch_json', return_value=({'ip': IP, 'country': 'Germany'}, None)) as fetch:
            report = lookup_reputation([IP], PROXY, credentials={})
        self.assertEqual(fetch.call_count, 1)
        self.assertEqual(report['status'], 'partial')
        self.assertEqual(report['ip_reports'][0]['coverage'], {'ipapi.is': 'partial', 'scamalytics': 'skipped', 'abuseipdb': 'skipped'})

    def test_keyed_ipapi_uses_post_abuseipdb_uses_header(self):
        with patch('ip_reputation.fetch_json', return_value=(ipapi(), None)) as fetch:
            lookup_provider('ipapi.is', IP, PROXY, {'IPAPI_IS_KEY': 'TEST_KEY'}, {})
            self.assertNotIn('TEST_KEY', fetch.call_args.args[0])
            self.assertEqual(fetch.call_args.kwargs['payload']['key'], 'TEST_KEY')
        with patch('ip_reputation.fetch_json', return_value=(abuse(), None)) as fetch:
            lookup_provider('abuseipdb', IP, PROXY, {'ABUSEIPDB_KEY': 'TEST_KEY'}, {})
            self.assertEqual(fetch.call_args.kwargs['headers']['Key'], 'TEST_KEY')
            self.assertNotIn('TEST_KEY', fetch.call_args.args[0])

    def test_scamalytics_region_and_credentials_are_not_returned(self):
        credentials = {'SCAMALYTICS_KEY': 'TEST_PRIVATE_KEY', 'SCAMALYTICS_USERNAME': 'TEST_USER', 'SCAMALYTICS_REGION': 'eu'}
        with patch('ip_reputation.fetch_json', return_value=(scam(), None)) as fetch:
            report = lookup_provider('scamalytics', IP, PROXY, credentials, {})
        self.assertTrue(fetch.call_args.args[0].startswith('https://api12.scamalytics.com/'))
        self.assertNotIn('TEST_PRIVATE_KEY', json.dumps(report))
        self.assertNotIn('TEST_USER', json.dumps(report))

    def test_http_429_cools_down_all_ips_for_that_provider(self):
        cache = {}
        with patch('ip_reputation.fetch_json', side_effect=FetchError('http_error', 429, 86400)) as fetch:
            first = lookup_provider('ipapi.is', IP, PROXY, {}, cache)
            second = lookup_provider('ipapi.is', '8.8.8.8', PROXY, {}, cache)
        self.assertEqual(fetch.call_count, 1)
        self.assertEqual(first['status'], 'rate_limited')
        self.assertEqual(second['reason'], 'provider_cooldown')
        self.assertGreater(second['retry_after_seconds'], 86000)

    def test_cache_keeps_source_timestamp_and_does_not_mutate_first_report(self):
        cache = {}
        with patch('ip_reputation.fetch_json', return_value=(ipapi(), None)) as fetch:
            first = lookup_provider('ipapi.is', IP, PROXY, {}, cache)
            second = lookup_provider('ipapi.is', IP, PROXY, {}, cache)
        self.assertEqual(fetch.call_count, 1)
        self.assertFalse(first['cache']['hit'])
        self.assertTrue(second['cache']['hit'])
        self.assertEqual(first['checked_at'], second['checked_at'])

    def test_http_200_application_error_or_exception_never_leaks_secret(self):
        for payload in ({'error': 'TEST_SECRET'}, {'ip': IP, 'company': []}):
            with patch('ip_reputation.fetch_json', return_value=(payload, None)):
                report = lookup_provider('ipapi.is', IP, PROXY, {}, {})
            self.assertNotIn('TEST_SECRET', json.dumps(report))
            self.assertNotEqual(report['status'], 'ok')
        with patch('ip_reputation.fetch_json', side_effect=OSError('https://api.example?key=TEST_SECRET')):
            report = lookup_provider('ipapi.is', IP, PROXY, {}, {})
        self.assertEqual(report['status'], 'error')
        self.assertNotIn('TEST_SECRET', json.dumps(report))

    def test_bad_credential_does_not_silently_retry_anonymous(self):
        with patch('ip_reputation.fetch_json', side_effect=FetchError('http_error', 403)) as fetch:
            report = lookup_provider('ipapi.is', IP, PROXY, {'IPAPI_IS_KEY': 'BAD_KEY'}, {})
        self.assertEqual(fetch.call_count, 1)
        self.assertEqual(report['status'], 'error')

    def test_expired_entries_are_removed(self):
        old_key = ('ipapi.is', '8.8.8.8')
        cache = {old_key: {'expires': 99, 'stored': 0, 'report': {}}}
        with patch('ip_reputation.time.monotonic', return_value=100), patch('ip_reputation.fetch_json', return_value=(ipapi(), None)):
            lookup_reputation([IP], PROXY, cache=cache, credentials={})
        self.assertNotIn(old_key, cache)

    def test_http_200_credit_exhaustion_is_not_a_valid_score(self):
        payload = {'scamalytics': {'status': 'error', 'error': 'TEST_SECRET', 'credits': {'remaining': 0}}}
        credentials = {'SCAMALYTICS_KEY': 'TEST_KEY', 'SCAMALYTICS_USERNAME': 'TEST_USER'}
        cache = {}
        with patch('ip_reputation.fetch_json', return_value=(payload, None)) as fetch:
            report = lookup_provider('scamalytics', IP, PROXY, credentials, cache)
            second = lookup_provider('scamalytics', '8.8.8.8', PROXY, credentials, cache)
        self.assertEqual(fetch.call_count, 1)
        self.assertEqual(report['status'], 'rate_limited')
        self.assertEqual(second['reason'], 'provider_cooldown')
        self.assertNotIn('TEST_SECRET', json.dumps(report))


class Collection(unittest.TestCase):
    def test_unverified_probe_never_queries_reputation(self):
        with patch('exit_probe.probe_exit', return_value={'status': 'unknown', 'ips': [IP]}), patch('ip_reputation.lookup_reputation') as lookup:
            report = collect_reputation(PROXY, 'Expected node', lambda: {})
        lookup.assert_not_called()
        self.assertEqual(report['status'], 'unknown')
        self.assertEqual(report['ip_reports'], [])

    def test_rotation_and_change_since_last_verified_check_are_explicit(self):
        probe = {'status': 'verified', 'ips': [IP, '8.8.8.8'], 'observed_stable': False}
        lookup = {'status': 'partial', 'ip_reports': [], 'warnings': []}
        with patch('exit_probe.probe_exit', return_value=probe), patch('ip_reputation.lookup_reputation', return_value=deepcopy(lookup)) as fetch:
            report = collect_reputation(PROXY, 'Expected node', lambda: {}, previous_ips=['8.8.8.8'])
        self.assertEqual(fetch.call_args.args[0], [IP, '8.8.8.8'])
        self.assertTrue(report['change_since_previous_check']['changed'])
        self.assertEqual(len(report['warnings']), 2)


if __name__ == '__main__':
    unittest.main()
