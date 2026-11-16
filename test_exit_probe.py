from contextlib import contextmanager
import json
import ssl
import unittest
from unittest.mock import MagicMock, patch

from exit_probe import FetchError, RouteError, fetch_json, https_tunnel, parse_proxy, probe_exit, verify_probe_route

PROXY = 'http://127.0.0.1:7890'


def entry(port=50000, source='127.0.0.1', host='api64.ipify.org', chains=None):
    return {'metadata': {'sourcePort': str(port), 'sourceIP': source, 'host': host, 'destinationPort': '443'},
            'chains': ['Expected node', 'Group'] if chains is None else chains, 'rule': 'Match', 'rulePayload': ''}


def snapshot(*rows):
    return {'connections': list(rows)}


class Correlation(unittest.TestCase):
    def verify(self, data):
        return verify_probe_route(data, ('127.0.0.1', 50000), 'api64.ipify.org', 'Expected node')

    def test_exact_socket_and_expected_endpoint(self):
        evidence = self.verify(snapshot(entry()))
        self.assertEqual(evidence['status'], 'verified')
        self.assertEqual(evidence['chain'], ['Group', 'Expected node'])

    def test_same_host_different_socket_cannot_verify_our_probe(self):
        self.assertEqual(self.verify(snapshot(entry(port=50001)))['status'], 'unknown')
        self.assertEqual(self.verify(snapshot(entry(source='127.0.0.2')))['status'], 'unknown')
        self.assertEqual(self.verify(snapshot(entry(host='elsewhere.example')))['status'], 'unknown')

    def test_duplicate_matches_and_missing_chain_are_unknown(self):
        self.assertEqual(self.verify(snapshot(entry(), entry()))['status'], 'unknown')
        self.assertEqual(self.verify(snapshot(entry(chains=[])))['status'], 'unknown')

    def test_direct_or_other_endpoint_is_mismatch(self):
        for endpoint in ('DIRECT', 'Other node'):
            self.assertEqual(self.verify(snapshot(entry(chains=[endpoint, 'Group'])))['status'], 'mismatch')

    def test_ipv4_mapped_loopback_correlates(self):
        self.assertEqual(self.verify(snapshot(entry(source='::ffff:127.0.0.1')))['status'], 'verified')


class Transport(unittest.TestCase):
    def fake_tunnel(self, response):
        connection = MagicMock()
        connection.sock.getsockname.return_value = ('127.0.0.1', 50000)
        connection.getresponse.return_value = response

        @contextmanager
        def tunnel(url, proxy):
            from urllib.parse import urlsplit
            yield connection, urlsplit(url)
        return connection, tunnel

    def test_route_mismatch_prevents_echo_request(self):
        connection, tunnel = self.fake_tunnel(MagicMock())
        with patch('exit_probe.https_tunnel', tunnel), self.assertRaises(RouteError):
            fetch_json('https://api64.ipify.org/?format=json', PROXY,
                       observe=lambda local, host: {'status': 'mismatch'})
        connection.request.assert_not_called()

    def test_post_key_is_in_body_and_redirects_are_not_followed(self):
        response = MagicMock(status=200)
        response.read.return_value = b'{"ip":"1.1.1.1"}'
        connection, tunnel = self.fake_tunnel(response)
        with patch('exit_probe.https_tunnel', tunnel):
            data, _ = fetch_json('https://api.ipapi.is/', PROXY, payload={'key': 'TEST_KEY'})
        call = connection.request.call_args
        self.assertEqual(call.args[:2], ('POST', '/'))
        self.assertEqual(json.loads(call.kwargs['body']), {'key': 'TEST_KEY'})
        self.assertEqual(data['ip'], '1.1.1.1')
        response.status = 302
        with patch('exit_probe.https_tunnel', tunnel), self.assertRaises(FetchError) as error:
            fetch_json('https://api.ipapi.is/', PROXY)
        self.assertEqual(error.exception.http_status, 302)

    def test_retry_after_and_response_size_limit(self):
        response = MagicMock(status=429)
        response.getheader.return_value = '3600'
        _, tunnel = self.fake_tunnel(response)
        with patch('exit_probe.https_tunnel', tunnel), self.assertRaises(FetchError) as error:
            fetch_json('https://api.ipapi.is/', PROXY)
        self.assertEqual(error.exception.retry_after, 3600)
        response.status = 200
        response.read.return_value = b'x' * (1024 * 1024 + 1)
        with patch('exit_probe.https_tunnel', tunnel), self.assertRaises(FetchError) as error:
            fetch_json('https://api.ipapi.is/', PROXY)
        self.assertEqual(error.exception.reason, 'response_too_large')

    def test_tls_failure_closes_connection_without_direct_fallback(self):
        with patch('exit_probe.http.client.HTTPSConnection') as cls, patch('exit_probe.ssl.create_default_context') as context:
            cls.return_value.connect.side_effect = ssl.SSLCertVerificationError('TEST_TLS_FAILURE')
            with self.assertRaises(ssl.SSLCertVerificationError):
                with https_tunnel('https://api64.ipify.org/', PROXY):
                    self.fail('Unverified TLS must never yield a connection')
            self.assertEqual(cls.call_count, 1)
            self.assertIs(cls.call_args.kwargs['context'], context.return_value)
            cls.return_value.close.assert_called_once()

    def test_proxy_auth_goes_only_to_connect_and_invalid_url_is_redacted(self):
        with patch('exit_probe.http.client.HTTPSConnection') as cls:
            with https_tunnel('https://api64.ipify.org/', 'http://user:TEST_PASSWORD@127.0.0.1:7890'):
                pass
            headers = cls.return_value.set_tunnel.call_args.kwargs['headers']
            self.assertTrue(headers['Proxy-Authorization'].startswith('Basic '))
        for proxy in ('socks5://127.0.0.1:7890', 'http://remote.example:7890', 'http://user:TEST_PASSWORD@remote.example:7890', None):
            with self.assertRaises(ValueError) as error:
                parse_proxy(proxy)
            self.assertNotIn('TEST_PASSWORD', str(error.exception))


class Sampling(unittest.TestCase):
    def test_rotating_ips_are_reported_not_collapsed_to_one(self):
        replies = [({'ip': ip}, {'status': 'verified'}) for ip in ('1.1.1.1', '8.8.8.8', '1.1.1.1')]
        with patch('exit_probe.fetch_json', side_effect=replies):
            report = probe_exit(PROXY, 'Expected node', lambda: snapshot())
        self.assertEqual(report['status'], 'verified')
        self.assertFalse(report['observed_stable'])
        self.assertEqual(report['ips'], ['1.1.1.1', '8.8.8.8'])

    def test_partial_route_or_tls_failure_is_not_stability(self):
        for error in (RouteError({'status': 'unknown'}), ssl.SSLCertVerificationError('TEST_SECRET')):
            replies = [({'ip': '1.1.1.1'}, {'status': 'verified'}), error,
                       ({'ip': '1.1.1.1'}, {'status': 'verified'})]
            with patch('exit_probe.fetch_json', side_effect=replies):
                report = probe_exit(PROXY, 'Expected node', lambda: snapshot())
            self.assertEqual(report['status'], 'unknown')
            self.assertIsNone(report['observed_stable'])
            self.assertNotIn('TEST_SECRET', json.dumps(report))

    def test_private_multicast_and_missing_echo_ips_are_rejected(self):
        for ip in ('127.0.0.1', '224.0.0.1', None):
            with patch('exit_probe.fetch_json', return_value=({'ip': ip}, {'status': 'verified'})):
                self.assertEqual(probe_exit(PROXY, 'Expected node', lambda: snapshot())['status'], 'unknown')


if __name__ == '__main__':
    unittest.main()
