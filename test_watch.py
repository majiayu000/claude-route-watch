import contextlib
import io
import json
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


if __name__ == '__main__':
    unittest.main()
