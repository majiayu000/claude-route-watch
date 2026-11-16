from copy import deepcopy
import contextlib
import io
import unittest

from ip_reputation import (base_report, normalize_abuseipdb, normalize_ipapi,
                           normalize_scamalytics, summarize_ip)
from terminal import print_ip_report, print_ip_details
from test_ip_reputation import IP, abuse, ipapi, scam


def sources():
    s = scam()
    s['scamalytics'].update(scamalytics_score=0, scamalytics_risk='low', is_blacklisted_external=False)
    s['scamalytics']['scamalytics_proxy']['is_datacenter'] = False
    s['external_datasources']['maxmind_geolite2']['ip_country_code'] = 'DE'
    s['external_datasources']['spamhaus_drop']['ip_blacklisted'] = False
    return [normalize_ipapi(ipapi(), IP), normalize_scamalytics(s, IP), normalize_abuseipdb(abuse(), IP)]


def rating(providers):
    return summarize_ip(IP, providers)['rating']


class EvidenceGrades(unittest.TestCase):
    def test_low_grade_requires_all_sources_and_preserves_original_metrics(self):
        providers = sources()
        before = deepcopy(providers)
        result = rating(providers)
        self.assertEqual(result['grade'], 'A')
        self.assertEqual(result['ready_sources'], 3)
        self.assertEqual(providers, before)
        self.assertNotIn('score', result)

    def test_scamalytics_boundary_bands_and_isp_score_is_not_ip_score(self):
        for value, grade in [(0, 'A'), (19, 'A'), (20, 'B'), (59, 'B'), (60, 'C'), (89, 'C'), (90, 'D'), (100, 'D')]:
            providers = sources()
            providers[1]['scores'][0]['value'] = value
            providers[1]['scores'][1]['value'] = 100
            self.assertEqual(rating(providers)['grade'], grade, value)

    def test_abuse_confidence_bands_are_explicit_own_policy(self):
        for value, grade in [(0, 'A'), (1, 'B'), (24, 'B'), (25, 'C'), (74, 'C'), (75, 'D'), (100, 'D')]:
            providers = sources()
            providers[2]['scores'][0]['value'] = value
            result = rating(providers)
            self.assertEqual(result['grade'], grade, value)
            self.assertTrue(any('本站' in reason for reason in result['reasons']))

    def test_bad_source_cannot_be_averaged_away(self):
        providers = sources()
        providers[2]['scores'][0]['value'] = 99
        self.assertEqual(rating(providers)['grade'], 'D')

    def test_anonymous_missing_failed_or_rate_limited_source_never_gets_grade(self):
        for state in ('partial', 'skipped', 'error', 'rate_limited', 'unknown'):
            providers = sources()
            providers[0]['status'] = state
            result = rating(providers)
            self.assertIsNone(result['grade'], state)
            self.assertEqual(result['incomplete_sources'], ['ipapi.is'])
        self.assertIsNone(rating(sources()[:2])['grade'])
        anonymous = normalize_ipapi({'ip': IP, 'country': 'Germany'}, IP)
        result = rating([anonymous, base_report('scamalytics', IP), base_report('abuseipdb', IP)])
        self.assertIsNone(result['grade'])
        self.assertEqual(result['ready_sources'], 0)

    def test_missing_source_does_not_hide_known_adverse_evidence(self):
        providers = sources()
        providers[0]['status'] = 'partial'
        providers[1]['scores'][0]['value'] = 99
        result = rating(providers)
        self.assertIsNone(result['grade'])
        self.assertTrue(any('99' in reason for reason in result['reasons']))

    def test_flags_reports_and_disagreements_are_explained(self):
        for index, field, expected in [(0, 'abuser', 'B'), (1, 'external_blacklist', 'C')]:
            providers = sources()
            providers[index]['flags'][field] = True
            self.assertEqual(rating(providers)['grade'], expected)
        providers = sources()
        providers[2]['details']['total_reports'] = 1
        self.assertEqual(rating(providers)['grade'], 'B')
        providers = sources()
        providers[1]['geo']['country_code'] = 'US'
        self.assertEqual(rating(providers)['grade'], 'B')
        providers = sources()
        providers[1]['flags']['vpn'] = True
        self.assertEqual(rating(providers)['grade'], 'B')  # Conflicting flags, not VPN alone.

    def test_consistent_datacenter_vpn_labels_do_not_automatically_deduct(self):
        providers = sources()
        for provider in providers[:2]:
            provider['flags']['datacenter'] = True
            provider['flags']['vpn'] = True
        self.assertEqual(rating(providers)['grade'], 'A')

    def test_existing_normalized_provider_cache_can_be_rated_without_migration(self):
        providers = sources()
        for provider in providers:
            self.assertNotIn('rating', provider)
            provider['cache'] = {'hit': True, 'age_seconds_at_lookup': 300}
        self.assertEqual(rating(providers)['grade'], 'A')

    def test_terminal_shows_grade_or_missing_evidence_with_reasons(self):
        for complete in (True, False):
            providers = sources()
            if not complete:
                providers[1]['status'] = 'skipped'
            item = summarize_ip(IP, providers)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                print_ip_report({'kind': 'machine_ip', 'ip_reports': [item]})
            text = output.getvalue()
            self.assertIn('IP 信誉 A · 已查来源低风险' if complete else '暂不评级', text)
            detail = io.StringIO()
            with contextlib.redirect_stdout(detail):
                print_ip_details({'kind': 'machine_ip', 'ip_reports': [item]})
            self.assertIn('规则 v1', detail.getvalue())
            if not complete:
                self.assertIn('尚缺完整证据：scamalytics', detail.getvalue())


if __name__ == '__main__':
    unittest.main()
