import contextlib
import io
import json
import ssl
import unittest
from unittest.mock import patch

from claude_route_watch import main
from exit_probe import FetchError, fetch_json, https_tunnel
from terminal import check_ip, menu, print_ip_report, print_ip_details, route_check
from test_ip_reputation import IP, ipapi


class DirectTransport(unittest.TestCase):
    def test_direct_does_not_use_environment_proxy_or_connect_tunnel(self):
        with patch.dict('os.environ', {'HTTPS_PROXY': 'http://credential:PRIVATE@proxy.example:9'}), \
                patch('exit_probe.http.client.HTTPSConnection') as cls:
            with https_tunnel('https://api64.ipify.org/?format=json', None):
                pass
        self.assertEqual(cls.call_args.args, ('api64.ipify.org', 443))
        cls.return_value.set_tunnel.assert_not_called()
        cls.return_value.close.assert_called_once()

    def test_direct_tls_failure_has_no_fallback_and_closes(self):
        with patch('exit_probe.http.client.HTTPSConnection') as cls:
            cls.return_value.connect.side_effect = ssl.SSLCertVerificationError('PRIVATE')
            with self.assertRaises(ssl.SSLCertVerificationError):
                with https_tunnel('https://api64.ipify.org/', None):
                    self.fail('Invalid TLS must not yield a direct connection')
        self.assertEqual(cls.call_count, 1)
        cls.return_value.close.assert_called_once()

    def test_attributed_path_cannot_silently_become_direct(self):
        with patch('exit_probe.https_tunnel') as transport, self.assertRaises(ValueError):
            fetch_json('https://api64.ipify.org/', None, observe=lambda *_: {'status': 'verified'})
        transport.assert_not_called()


class MachineIP(unittest.TestCase):
    def test_echo_is_used_for_exact_ip_query_and_no_keys_stay_partial(self):
        with patch('terminal.fetch_json', return_value=({'ip': IP}, None)) as echo, \
                patch('ip_reputation.fetch_json', return_value=(ipapi(), None)) as source:
            report = check_ip(credentials={})
        self.assertEqual(echo.call_args.args[1], None)
        self.assertEqual(source.call_count, 1)
        self.assertEqual(source.call_args.args[1], None)
        self.assertIn('q=' + IP, source.call_args.args[0])
        self.assertEqual(report['status'], 'partial')
        self.assertEqual(report['probe']['status'], 'observed')
        self.assertEqual(report['kind'], 'machine_ip')
        self.assertEqual(report['ip_reports'][0]['coverage']['abuseipdb'], 'skipped')
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            print_ip_report(report)
        self.assertIn('未配置', output.getvalue())
        self.assertIn('非 Claude 实际出口', output.getvalue())
        self.assertNotIn('VPN：未知', output.getvalue())

    def test_bad_or_failed_echo_never_queries_reputation(self):
        for payload in ({}, {'ip': '127.0.0.1'}, {'ip': '224.0.0.1'}):
            with patch('terminal.fetch_json', return_value=(payload, None)), \
                    patch('terminal.lookup_reputation') as lookup:
                self.assertEqual(check_ip(credentials={})['status'], 'unknown')
                lookup.assert_not_called()
        with patch('terminal.fetch_json', side_effect=OSError('https://example?key=PRIVATE')), \
                patch('terminal.lookup_reputation') as lookup:
            report = check_ip(credentials={})
        lookup.assert_not_called()
        self.assertNotIn('PRIVATE', json.dumps(report))

    def test_http_failure_does_not_print_response_or_credentials(self):
        with patch('terminal.fetch_json', side_effect=FetchError('http_error', 429)):
            report = check_ip(credentials={})
        self.assertEqual(report['status'], 'unknown')
        self.assertEqual(report['probe']['http_status'], 429)

    def test_cli_json_and_environment_proxy_do_not_change_direct_mode(self):
        output = io.StringIO()
        with patch.dict('os.environ', {'CLAUDE_ROUTE_PROXY': 'http://private@127.0.0.1:1'}), \
                patch('terminal.check_ip', return_value={'status': 'partial', 'kind': 'machine_ip'}) as check, \
                contextlib.redirect_stdout(output):
            self.assertEqual(main(['--ip', '--json']), 2)
        check.assert_called_once_with()
        self.assertEqual(json.loads(output.getvalue())['kind'], 'machine_ip')

    def test_direct_and_routed_options_cannot_be_combined(self):
        for args in (['--ip', '--proxy', 'http://127.0.0.1:9'], ['--ip', '--watch'],
                     ['--ip', '--expect', 'Node'], ['--ip', '--reputation']):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                main(args)
            self.assertEqual(error.exception.code, 2)


class TerminalMenu(unittest.TestCase):
    def test_no_arguments_shows_menu_and_exit_does_not_access_network(self):
        output = io.StringIO()
        with patch('sys.stdin.isatty', return_value=True), patch('builtins.input', return_value='0'), \
                patch('terminal.check_ip') as ip, patch('claude_route_watch.request') as request, \
                contextlib.redirect_stdout(output):
            self.assertEqual(main([]), 0)
        self.assertIn('无需 Clash', output.getvalue())
        ip.assert_not_called()
        request.assert_not_called()

    def test_non_tty_and_help_never_probe(self):
        with patch('sys.stdin.isatty', return_value=False), patch('terminal.check_ip') as ip, \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(menu(), 2)
        ip.assert_not_called()
        with patch('terminal.check_ip') as ip, contextlib.redirect_stdout(io.StringIO()), \
                self.assertRaises(SystemExit) as result:
            main(['--help'])
        self.assertEqual(result.exception.code, 0)
        ip.assert_not_called()

    def test_current_node_is_not_automatically_the_expected_node(self):
        def runtime(endpoint, *args):
            if endpoint == '/configs':
                return {'mixed-port': 7890}
            if endpoint == '/proxies':
                return {'proxies': {'A expected': {'type': 'Vless'}, 'Z observed': {'type': 'Vless'},
                                    'Group': {'type': 'Selector', 'all': ['Z observed']}}}
            return {'connections': [{'metadata': {'host': 'api.anthropic.com'},
                                      'chains': ['Z observed', 'Group']}]}
        with patch('claude_route_watch.request', side_effect=runtime), \
                patch('builtins.input', side_effect=['1', 'n', '']), patch('claude_route_watch.main') as run, \
                contextlib.redirect_stdout(io.StringIO()):
            route_check()
        self.assertEqual(run.call_args.args[0], ['--expect', 'A expected'])

    def test_port_is_discovered_but_reputation_needs_user_choice(self):
        def runtime(endpoint, *args):
            if endpoint == '/configs':
                return {'mixed-port': 17890}
            if endpoint == '/proxies':
                return {'proxies': {'Node': {'type': 'Trojan'}}}
            return {'connections': []}
        with patch('claude_route_watch.request', side_effect=runtime), \
                patch('builtins.input', side_effect=['1', 'y']), patch('claude_route_watch.main') as run, \
                contextlib.redirect_stdout(io.StringIO()):
            route_check('/config', '/sock', watch=True)
        self.assertEqual(run.call_args.args[0], ['--expect', 'Node', '--config', '/config', '--socket', '/sock',
                                               '--reputation', '--proxy', 'http://127.0.0.1:17890', '--watch'])

    def test_missing_controller_is_actionable_without_raw_error(self):
        output = io.StringIO()
        with patch('claude_route_watch.request', side_effect=OSError('PRIVATE_ERROR_NOT_PRINT')), contextlib.redirect_stdout(output):
            self.assertEqual(route_check(), 2)
        self.assertIn('--socket', output.getvalue())
        self.assertNotIn('PRIVATE_ERROR_NOT_PRINT', output.getvalue())

    def test_interrupting_watch_exits_menu_instead_of_leaving_queries_running(self):
        with patch('sys.stdin.isatty', return_value=True), patch('builtins.input', return_value='3'), \
                patch('terminal.route_check', side_effect=KeyboardInterrupt) as watch, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(menu(), 0)
        watch.assert_called_once_with(None, None, watch=True)

    def test_summary_fits_common_widths_and_keeps_unknowns_in_details(self):
        from terminal import cell_width
        from ip_reputation import normalize_ipapi, base_report, summarize_ip
        source = normalize_ipapi({'ip': IP, 'country': 'United States', 'company': 'A long owner ' * 20}, IP)
        item = summarize_ip(IP, [source, base_report('scamalytics', IP), base_report('abuseipdb', IP)])
        report = {'kind': 'machine_ip', 'ip_reports': [item]}
        for columns in (40, 80):
            output = io.StringIO()
            import os
            with patch('terminal.shutil.get_terminal_size', return_value=os.terminal_size((columns, 24))), contextlib.redirect_stdout(output):
                print_ip_report(report)
            lines = output.getvalue().splitlines()
            self.assertLessEqual(len(lines), 24)
            self.assertTrue(all(cell_width(line) <= columns for line in lines))
            self.assertIn('暂不评级', output.getvalue())
            self.assertNotIn('VPN：未知', output.getvalue())
        detail = io.StringIO()
        with contextlib.redirect_stdout(detail):
            print_ip_details(report)
        self.assertIn('VPN：未知', detail.getvalue())

    def test_details_reuses_the_report_instead_of_querying_again(self):
        from terminal import inspect_ip_report
        report = {'kind': 'machine_ip', 'ip_reports': [], 'probe': {'reason': 'echo_unavailable'}}
        with patch('builtins.input', side_effect=['d', '']), patch('terminal.check_ip') as query, contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(inspect_ip_report(report))
        query.assert_not_called()

    def test_colors_are_tty_only_and_respect_no_color(self):
        from terminal import paint
        with patch('sys.stdout.isatty', return_value=True), patch.dict('os.environ', {'TERM': 'xterm'}, clear=True):
            self.assertIn('\033[', paint('暂不评级', '33'))
            with patch.dict('os.environ', {'NO_COLOR': ''}):
                self.assertEqual(paint('暂不评级', '33'), '暂不评级')
        with patch('sys.stdout.isatty', return_value=False):
            self.assertEqual(paint('暂不评级', '33'), '暂不评级')

    def test_remote_terminal_controls_are_not_emitted(self):
        output = io.StringIO()
        report = {'status': 'unknown', 'probe': {'reason': '\x1b[2JPRIVATE\n'}, 'ip_reports': []}
        with contextlib.redirect_stdout(output):
            print_ip_report(report)
        self.assertNotIn('\x1b', output.getvalue())


if __name__ == '__main__':
    unittest.main()
