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
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'settings.json'
        self.notifier = Mock()
        self.state = DesktopState(self.path, reader=runtime, notifier=self.notifier)
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
        self.api.begin('Other node')
        self.state._sample_once()
        data = self.api.get_status()
        self.assertTrue(data['route']['issues'])
        self.assertTrue(data['notification_error'])
        self.assertNotIn('TEST_PRIVATE_VALUE', json.dumps(data))
        self.assertFalse(self.api.test_notification()['ok'])


if __name__ == '__main__':
    unittest.main()
