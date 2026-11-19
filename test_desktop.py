import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from desktop import DesktopAPI, DesktopState


def runtime(endpoint):
    return {
        '/configs': {'mixed-port': 7890, 'tun': {'enable': True}},
        '/connections': {'connections': [{'metadata': {'host': 'api.anthropic.com', 'process': 'claude'}, 'chains': ['Observed node', 'Any group']}]},
        '/proxies': {'proxies': {'Observed node': {'type': 'Shadowsocks'}, 'Other node': {'type': 'VLESS'},
                                'DIRECT': {'type': 'Direct'}, 'Any group': {'type': 'Selector', 'all': ['Observed node']}}},
    }[endpoint]


class Desktop(unittest.TestCase):
    def setUp(self):
        self.environment = patch.dict('os.environ', {}, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'settings.json'
        self.notifier = Mock()
        self.runtime = {path: runtime(path) for path in ('/configs', '/connections', '/proxies')}
        self.state = DesktopState(self.path, reader=self.runtime.__getitem__, notifier=self.notifier,
                                  collector=Mock(side_effect=AssertionError('Unexpected external lookup')))
        self.addCleanup(self.state._close)
        self.api = DesktopAPI(self.state)

    def test_discovery_requires_no_user_port_and_does_not_silently_pin(self):
        self.state._sample_once()
        data = self.api.get_status()
        self.assertEqual(data['suggested'], 'Observed node')
        self.assertEqual(data['nodes'], ['Observed node', 'Other node'])
        self.assertTrue(data['proxy_available'])
        self.assertFalse(data['monitoring'])
        self.assertFalse(self.path.exists())

    def test_one_click_saves_explicit_baseline_and_resumes(self):
        self.state._sample_once()
        self.assertTrue(self.api.begin('Observed node')['ok'])
        self.state._sample_once()
        self.assertEqual(self.api.get_status()['route']['score'], 100)
        saved = json.loads(self.path.read_text())
        self.assertEqual(saved['expected'], 'Observed node')
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        restored = DesktopState(self.path, reader=runtime, notifier=self.notifier)
        self.addCleanup(restored._close)
        self.assertTrue(restored._status()['monitoring'])
        self.assertEqual(restored._status()['expected'], 'Observed node')

    def test_changed_route_is_not_adopted_as_new_baseline(self):
        self.state._sample_once()
        self.api.begin('Other node')
        self.state._sample_once()
        data = self.api.get_status()
        self.assertEqual(data['expected'], 'Other node')
        self.assertLess(data['route']['score'], 40)
        self.assertEqual(json.loads(self.path.read_text())['expected'], 'Other node')
        self.assertEqual(data['exit']['status'], 'unknown')
        self.notifier.assert_not_called()

    def test_unknown_node_and_direct_cannot_be_pinned(self):
        self.state._sample_once()
        self.assertFalse(self.api.begin('DIRECT')['ok'])
        self.assertFalse(self.api.begin('not a configured proxy')['ok'])
        self.assertFalse(self.path.exists())

    def test_pause_is_remembered(self):
        self.state._sample_once()
        self.api.begin('Observed node')
        self.api.pause()
        self.assertFalse(self.api.get_status()['monitoring'])
        restored = DesktopState(self.path)
        self.addCleanup(restored._close)
        self.assertFalse(restored._status()['monitoring'])

    def test_credentials_are_neither_persisted_nor_returned(self):
        self.state._sample_once()
        self.api.begin('Observed node')
        self.assertTrue(self.api.save_credentials({'IPAPI_IS_KEY': 'TEST_PRIVATE_VALUE'})['ok'])
        self.assertTrue(self.api.get_status()['credentials_available']['ipapi.is'])
        self.assertNotIn('TEST_PRIVATE_VALUE', json.dumps(self.api.get_status()))
        self.assertNotIn('TEST_PRIVATE_VALUE', self.path.read_text())
        self.api.clear_credentials()
        self.assertFalse(self.api.get_status()['credentials_available']['ipapi.is'])

    def test_ip_queries_are_opt_in_and_session_only(self):
        called = threading.Event()
        def result(*args, **kwargs):
            called.set()
            return {'status': 'partial', 'warnings': [], 'ip_reports': []}
        collector = Mock(side_effect=result)
        self.state._collector = collector
        self.state._sample_once()
        self.api.begin('Observed node')
        self.state._sample_once()
        collector.assert_not_called()
        self.assertTrue(self.api.set_ip(True)['ok'])
        self.state._sample_once()
        self.assertTrue(called.wait(1))
        self.assertTrue(collector.called)
        restored = DesktopState(self.path)
        self.addCleanup(restored._close)
        self.assertFalse(restored._status()['ip_enabled'])

    def test_stale_job_result_is_discarded_after_baseline_change(self):
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()
        def blocked(*args, **kwargs):
            entered.set()
            release.wait(3)
            return {'status': 'complete', 'warnings': [], 'ip_reports': [], 'marker': 'OLD_BASELINE'}
        self.state._collector = blocked
        self.state._sample_once()
        self.api.begin('Observed node')
        self.api.set_ip(True)
        old_check = self.state._check_ip
        def checked(*args):
            try:
                old_check(*args)
            finally:
                finished.set()
        self.state._check_ip = checked
        try:
            self.state._sample_once()
            self.assertTrue(entered.wait(1))
            self.api.begin('Other node')
            release.set()
            self.assertTrue(finished.wait(2))
            self.assertIsNone(self.api.get_status()['reputation'])
        finally:
            release.set()

    def test_unreadable_settings_remain_untouched_until_explicit_selection(self):
        self.path.write_text('{not-json')
        model = DesktopState(self.path, reader=runtime)
        self.addCleanup(model._close)
        self.assertTrue(model._status()['settings_error'])
        model._sample_once()
        self.assertEqual(self.path.read_text(), '{not-json')
        self.assertFalse(model._status()['monitoring'])

    def test_disconnected_controller_is_unknown_not_old_green_data(self):
        self.state._sample_once()
        self.api.begin('Observed node')
        self.state._sample_once()
        self.state._reader = Mock(side_effect=OSError('TEST_SECRET'))
        self.state._sample_once()
        data = self.api.get_status()
        self.assertFalse(data['connected'])
        self.assertIsNone(data['route'])
        self.assertNotIn('TEST_SECRET', json.dumps(data))

    def test_no_http_port_keeps_route_monitor_but_disables_ip_probe(self):
        def reader(endpoint):
            return {'tun': {'enable': True}, 'mixed-port': 0, 'port': 0} if endpoint == '/configs' else runtime(endpoint)
        self.state._reader = reader
        self.state._sample_once()
        self.api.begin('Observed node')
        self.state._sample_once()
        self.assertEqual(self.api.get_status()['route']['score'], 100)
        self.assertFalse(self.api.set_ip(True)['ok'])

    def test_notification_failure_does_not_hide_route_warning(self):
        self.state._notifier = Mock(side_effect=OSError('TEST_PRIVATE_VALUE'))
        self.state._sample_once()
        self.api.begin('Observed node')
        self.runtime['/connections']['connections'][0]['chains'] = ['DIRECT']
        self.state._sample_once()
        data = self.api.get_status()
        self.assertTrue(data['route']['issues'])
        self.assertTrue(data['notification_error'])
        self.assertNotIn('TEST_PRIVATE_VALUE', json.dumps(data))
        self.assertFalse(self.api.test_notification()['ok'])

    def start_exit_monitor(self):
        self.state._sample_once()
        self.assertTrue(self.api.begin('Observed node')['ok'])
        self.assertTrue(self.api.set_ip(True)['ok'])

    def check_exit(self, ips=None, *, verified=True):
        ips = ['1.1.1.1'] if ips is None else ips
        self.state._collector = Mock(return_value={
            'status': 'partial', 'warnings': ['Some reputation providers are unavailable'], 'ip_reports': [],
            'probe': {'status': 'verified' if verified else 'unknown', 'ips': ips,
                      'observed_stable': len(ips) == 1, 'checked_at': '2026-11-16T00:00:00+00:00'},
        })
        self.state._next_ip_check = 0
        # Keep the real scheduling path while completing the mocked lookup deterministically.
        with patch('desktop.threading.Thread') as worker:
            worker.side_effect = lambda *, target, args, daemon: Mock(start=lambda: target(*args))
            self.state._sample_once()
        return self.api.get_status()

    def test_same_public_exit_on_renamed_node_stays_quiet(self):
        self.start_exit_monitor()
        self.assertEqual(self.check_exit()['exit']['status'], 'matches')
        self.runtime['/connections']['connections'][0]['chains'] = ['Other node', 'Any group']
        data = self.check_exit()
        self.assertEqual(data['exit']['status'], 'matches')
        self.assertEqual(data['exit']['baseline_ips'], ['1.1.1.1'])
        self.assertEqual(data['expected'], 'Observed node')
        self.assertEqual(self.state._collector.call_args.args[1], 'Other node')
        self.notifier.assert_not_called()

    def test_changed_ip_on_same_node_alerts_once_and_keeps_baseline(self):
        self.start_exit_monitor()
        self.check_exit()
        for _ in range(2):
            data = self.check_exit(['8.8.8.8'])
            self.assertEqual(data['exit']['status'], 'changed')
        self.notifier.assert_called_once()
        self.assertIn('1.1.1.1', self.notifier.call_args.args[1])
        self.assertIn('8.8.8.8', self.notifier.call_args.args[1])
        self.assertEqual(json.loads(self.path.read_text())['baseline_ips'], ['1.1.1.1'])

    def test_unknown_after_alarm_is_not_a_recovery_or_repeated_alarm(self):
        self.start_exit_monitor()
        self.check_exit()
        self.check_exit(['8.8.8.8'])
        self.assertEqual(self.check_exit([], verified=False)['exit']['status'], 'unknown')
        self.check_exit(['8.8.8.8'])
        self.assertEqual(self.notifier.call_count, 1)
        self.check_exit()
        self.assertEqual(self.notifier.call_count, 2)
        self.assertIn('恢复', self.notifier.call_args.args[1])

    def test_rotating_exit_does_not_seed_baseline_and_later_change_alerts(self):
        self.start_exit_monitor()
        self.assertEqual(self.check_exit(['1.1.1.1', '8.8.8.8'])['exit']['status'], 'unknown')
        self.assertIsNone(json.loads(self.path.read_text())['baseline_ips'])
        self.check_exit()
        self.assertEqual(self.check_exit(['1.1.1.1', '8.8.8.8'])['exit']['status'], 'changed')

    def test_different_node_cannot_silently_establish_first_baseline(self):
        self.start_exit_monitor()
        self.runtime['/connections']['connections'][0]['chains'] = ['Other node']
        data = self.check_exit()
        self.assertEqual(data['exit']['status'], 'unknown')
        self.assertIsNone(data['exit']['baseline_ips'])
        self.notifier.assert_not_called()
        self.api.begin('Other node')
        self.assertEqual(self.check_exit()['exit']['status'], 'matches')

    def test_baseline_survives_restart_and_ip_toggle_but_explicit_reset_clears_it(self):
        self.start_exit_monitor()
        self.check_exit()
        self.api.set_notifications(False)
        self.api.set_ip(False)
        self.assertEqual(self.api.get_status()['exit']['status'], 'unknown')
        self.api.pause()
        restored = DesktopState(self.path)
        self.addCleanup(restored._close)
        self.assertEqual(restored._status()['exit']['baseline_ips'], ['1.1.1.1'])
        self.assertFalse(restored._status()['ip_enabled'])
        self.runtime['/connections']['connections'][0]['chains'] = ['Other node']
        self.api.begin('Other node')
        self.api.set_ip(True)
        self.assertEqual(self.check_exit(['8.8.8.8'])['exit']['status'], 'changed')
        self.assertEqual(json.loads(self.path.read_text())['baseline_ips'], ['1.1.1.1'])
        self.api.begin('Observed node')
        self.assertIsNone(json.loads(self.path.read_text())['baseline_ips'])

    def test_invalid_saved_exit_pauses_instead_of_replacing_baseline(self):
        self.path.write_text(json.dumps({'expected': 'Observed node', 'monitoring': True, 'baseline_ips': []}))
        model = DesktopState(self.path, reader=runtime)
        self.addCleanup(model._close)
        self.assertFalse(model._status()['monitoring'])
        self.assertTrue(model._status()['settings_error'])
        self.assertEqual(json.loads(self.path.read_text())['baseline_ips'], [])

    def test_no_connections_missing_chain_or_mixed_nodes_never_claim_exit_match(self):
        self.start_exit_monitor()
        self.check_exit()
        for connections in ([], [{'metadata': {'host': 'api.anthropic.com'}, 'chains': []}],
                            [{'metadata': {'host': 'api.anthropic.com'}, 'chains': [node]} for node in ('Observed node', 'Other node')]):
            self.runtime['/connections']['connections'] = connections
            data = self.check_exit()
            self.assertEqual(data['exit']['status'], 'unknown')
            self.state._collector.assert_not_called()
        self.notifier.assert_not_called()

    def test_direct_alert_is_deduplicated_across_host_changes_without_ip_queries(self):
        self.state._sample_once()
        self.api.begin('Observed node')
        for host in ('api.anthropic.com', 'bridge.claudeusercontent.com'):
            self.runtime['/connections']['connections'] = [{'metadata': {'host': host}, 'chains': ['DIRECT']}]
            self.state._sample_once()
            self.assertEqual(self.api.get_status()['exit']['status'], 'direct')
        self.notifier.assert_called_once()
        self.state._collector.assert_not_called()

    def test_route_change_invalidates_inflight_probe_even_if_it_returns_to_old_node(self):
        self.start_exit_monitor()
        self.check_exit()
        old_revision = self.state._revision
        self.state._ip_busy = True
        for node in ('Other node', 'Observed node'):
            self.runtime['/connections']['connections'][0]['chains'] = [node]
            self.state._sample_once()
        self.state._check_ip(old_revision, 'http://127.0.0.1:7890', 'Observed node', {}, {}, None)
        self.assertIsNone(self.api.get_status()['reputation'])
        self.assertEqual(self.api.get_status()['exit']['status'], 'unknown')

    def test_failed_baseline_save_never_claims_exit_match(self):
        self.start_exit_monitor()
        with patch.object(self.state, '_save', side_effect=OSError('TEST_PRIVATE_VALUE')):
            data = self.check_exit()
        self.assertIsNone(data['exit']['baseline_ips'])
        self.assertEqual(data['exit']['status'], 'unknown')
        self.assertTrue(data['settings_error'])
        self.assertNotIn('TEST_PRIVATE_VALUE', json.dumps(data))
        self.notifier.assert_not_called()

    def test_notifications_off_does_not_hide_changed_exit(self):
        self.start_exit_monitor()
        self.check_exit()
        self.api.set_notifications(False)
        self.assertEqual(self.check_exit(['8.8.8.8'])['exit']['status'], 'changed')
        self.notifier.assert_not_called()


if __name__ == '__main__':
    unittest.main()
