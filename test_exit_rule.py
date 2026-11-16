"""The user's rule (2026-11-16): the exit is what matters; a switched node with the same exit IP is only a record."""
import contextlib
import io
import unittest
from unittest.mock import patch

from claude_route_watch import main


class SyncThread:
    def __init__(self, target, args=(), daemon=None):
        self.target, self.args = target, args

    def start(self):
        self.target(*self.args)


def watch(nodes, ips, ticks):
    """Run watch mode for `ticks` samples; Claude uses nodes[i] and the probe sees ips[node]."""
    reports, tick = [], {'n': 0}

    def runtime(endpoint, *args):
        if endpoint == '/configs':
            return {'tun': {'enable': True}}
        node = nodes[min(tick['n'], len(nodes) - 1)]
        return {'connections': [{'metadata': {'host': 'api.anthropic.com'}, 'chains': [node, 'AI']}]}

    def probe(proxy, node, read, cache=None, previous_ips=None):
        return {'status': 'partial', 'ip_reports': [], 'warnings': [],
                'probe': {'status': 'verified', 'ips': [ips[node]], 'observed_stable': True}}

    def collect(report):
        reports.append(report)

    def sleep(_):
        tick['n'] += 1
        if tick['n'] >= ticks:
            raise KeyboardInterrupt

    with patch('claude_route_watch.request', side_effect=runtime), \
            patch('claude_route_watch.collect_reputation', side_effect=probe), \
            patch('claude_route_watch.threading.Thread', SyncThread), \
            patch('claude_route_watch.time.sleep', side_effect=sleep), \
            contextlib.redirect_stdout(io.StringIO()), contextlib.suppress(KeyboardInterrupt):
        main(['--expect', 'Node', '--watch', '--reputation', '--proxy', 'http://127.0.0.1:7890',
              '--reputation-interval', '0.000001', '--interval', '1'], report_output=collect)
    return reports


class ExitRule(unittest.TestCase):
    def test_switched_node_with_same_exit_is_not_an_issue(self):
        reports = watch(['Node', 'Node', 'Other', 'Other', 'Other'], {'Node': '8.8.8.8', 'Other': '8.8.8.8'}, 6)
        last = reports[-1]
        self.assertEqual(last['observed_endpoints'], ['Other'])
        self.assertEqual(last['exit']['status'], 'matches')
        self.assertEqual(last['issues'], [])
        self.assertTrue(last['node_changes'])

    def test_changed_exit_is_an_issue(self):
        reports = watch(['Node', 'Node', 'Other', 'Other'], {'Node': '8.8.8.8', 'Other': '9.9.9.9'}, 5)
        last = reports[-1]
        self.assertEqual(last['exit']['status'], 'changed')
        self.assertTrue(any(item.startswith('Exit IP changed') for item in last['issues']))

    def test_old_exit_is_never_compared_to_a_new_node(self):
        reports = watch(['Node', 'Node', 'Other'], {'Node': '8.8.8.8', 'Other': '9.9.9.9'}, 4)
        first_other = next(r for r in reports if r['observed_endpoints'] == ['Other'])
        self.assertIn(first_other['exit']['status'], ('pending', 'changed'))
        self.assertNotEqual(first_other['exit']['status'], 'matches')


if __name__ == '__main__':
    unittest.main()
