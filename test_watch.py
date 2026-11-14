import contextlib
import io
import json
import threading
import unittest
from unittest.mock import patch
from claude_route_watch import analyze, main, request


def connection(endpoint, host='api.anthropic.com', process='claude'):
    return {'metadata': {'host': host, 'process': process},
            'chains': [endpoint, 'Example group'] if endpoint else []}


def score(rows, tun=True):
    return analyze({'tun': {'enable': tun}}, {'connections': rows}, 'Expected proxy')


class Routes(unittest.TestCase):
    def test_expected_proxy_scores_100_without_specific_group_name(self):
        self.assertEqual(score([connection('Expected proxy')])['score'], 100)

    def test_direct_cannot_be_diluted_by_normal_connections(self):
        rows = [connection('Expected proxy') for _ in range(1000)]
        self.assertEqual(score(rows + [connection('DIRECT')])['score'], 0)

    def test_wrong_endpoint_capped(self):
        rows = [connection('Expected proxy') for _ in range(1000)]
        self.assertLessEqual(score(rows + [connection('Other proxy')])['score'], 39)

    def test_mixed_endpoints_lose_consistency_points(self):
        report = score([connection('Expected proxy'), connection('Old proxy')])
        self.assertEqual(report['components']['endpoint_consistency'], 0)
        self.assertIn('Old proxy', str(report['issues']))

    def test_empty_and_missing_chain_are_unknown(self):
        self.assertIsNone(score([])['score'])
        self.assertIsNone(score([connection(None)])['score'])
        self.assertIsNone(score([connection(None), connection('Expected proxy')])['score'])

    def test_direct_takes_precedence_over_unknown_peer(self):
        self.assertEqual(score([connection(None), connection('DIRECT')])['score'], 0)

    def test_native_version_process_includes_datadog(self):
        row = connection('DIRECT', 'http-intake.logs.us5.datadoghq.com', '2.1.323')
        row['metadata']['processPath'] = '/Users/example/.local/share/claude/versions/2.1.323'
        self.assertEqual(score([row])['score'], 0)

    def test_browser_auth_included_unrelated_sentry_excluded(self):
        self.assertEqual(score([connection('DIRECT', 'platform.claude.com', 'Chrome')])['score'], 0)
        self.assertEqual(score([connection('DIRECT', 'x.sentry.io', 'Chrome')])['observed_connections'], 0)

    def test_suffix_matching_does_not_accept_impostor(self):
        row = connection('DIRECT', 'anthropic.com.example.org', 'Chrome')
        self.assertEqual(score([row])['observed_connections'], 0)

    def test_tun_off_reduces_observed_score_and_warns(self):
        report = score([connection('Expected proxy')], tun=False)
        self.assertEqual(report['score'], 80)
        self.assertTrue(report['issues'])

    def test_direct_cannot_be_expected(self):
        with self.assertRaises(ValueError):
            analyze({}, {'connections': []}, 'DIRECT')

    def test_missing_socket_fails(self):
        with patch('claude_route_watch.Path.exists', return_value=False), patch('claude_route_watch.Path.is_socket', return_value=False):
            with self.assertRaises(RuntimeError):
                request('/connections')

    def test_empty_secret_does_not_consume_next_yaml_line(self):
        with patch.dict('os.environ', {}, clear=True), patch('claude_route_watch.Path.exists', return_value=True), patch('claude_route_watch.Path.is_socket', return_value=True), patch('claude_route_watch.Path.read_text', return_value="secret: ''\nmode: rule\n"), patch('claude_route_watch.UnixHTTP') as client:
            response = client.return_value.getresponse.return_value
            response.status = 200
            response.read.return_value = b'{"connections": []}'
            request('/connections')
            client.return_value.request.assert_called_once_with('GET', '/connections', headers={'Authorization': 'Bearer '})

    def test_cli_api_failure_returns_unknown_without_leaking_error(self):
        output = io.StringIO()
        with patch('sys.argv', ['watch', '--expect', 'Expected proxy']), contextlib.redirect_stdout(output), patch('claude_route_watch.request', side_effect=OSError('secret-do-not-print')):
            self.assertEqual(main(), 2)
        report = json.loads(output.getvalue())
        self.assertIsNone(report['score'])
        self.assertNotIn('secret-do-not-print', output.getvalue())


class ReputationCLI(unittest.TestCase):
    def runtime(self, endpoint, *args):
        if endpoint == '/configs':
            return {'tun': {'enable': True}}
        return {'connections': [connection('Expected proxy')]}

    def test_default_mode_does_not_contact_reputation_services(self):
        with patch('sys.argv', ['watch', '--expect', 'Expected proxy']), patch('claude_route_watch.request', side_effect=self.runtime), patch('claude_route_watch.collect_reputation') as collect, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(), 0)
        collect.assert_not_called()

    def test_missing_proxy_is_rejected_without_exposing_url(self):
        with patch.dict('os.environ', {}, clear=True), patch('sys.argv', ['watch', '--expect', 'Expected proxy', '--reputation']), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                main()
        self.assertEqual(error.exception.code, 2)

    def test_partial_reputation_does_not_inflate_or_reduce_routing_score(self):
        output = io.StringIO()
        args = ['watch', '--expect', 'Expected proxy', '--reputation', '--proxy', 'http://127.0.0.1:7890']
        with patch('sys.argv', args), patch('claude_route_watch.request', side_effect=self.runtime), patch('claude_route_watch.collect_reputation', return_value={'status': 'partial', 'ip_reports': [], 'warnings': []}), contextlib.redirect_stdout(output):
            self.assertEqual(main(), 2)
        report = json.loads(output.getvalue())
        self.assertEqual(report['score'], 100)
        self.assertEqual(report['reputation']['status'], 'partial')
        self.assertNotIn('score', report['reputation'])

    def test_vendor_failure_does_not_block_the_watch_sampler(self):
        release, finished = threading.Event(), threading.Event()

        def blocked_vendor(*args, **kwargs):
            release.wait(3)
            finished.set()
            return {'status': 'unknown', 'ip_reports': [], 'warnings': []}

        args = ['watch', '--expect', 'Expected proxy', '--watch', '--duration', '0.03', '--interval', '0.01',
                '--reputation', '--proxy', 'http://127.0.0.1:7890']
        output = io.StringIO()
        try:
            with patch('sys.argv', args), patch('claude_route_watch.request', side_effect=self.runtime) as read, patch('claude_route_watch.collect_reputation', side_effect=blocked_vendor), contextlib.redirect_stdout(output):
                self.assertEqual(main(), 2)
                self.assertFalse(finished.is_set())
                self.assertGreater(read.call_count, 2)
            self.assertEqual(json.loads(output.getvalue().splitlines()[-1])['reputation']['status'], 'pending')
        finally:
            release.set()
            finished.wait(2)


if __name__ == '__main__':
    unittest.main()
