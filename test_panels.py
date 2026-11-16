import io
import os
import unittest
from unittest.mock import patch

import panels
import views
from exit_probe import set_progress
from ip_reputation import lookup_reputation, summarize_ip
from test_ip_reputation import IP, ipapi
from test_ratings import sources


def item(scam_score=0):
    providers = sources()
    providers[1]['scores'][0]['value'] = scam_score
    return summarize_ip(IP, providers)


def route(endpoints=('Node',), issues=(), reputation=None):
    report = {'score': 100 if not issues else 39, 'expected': 'Node', 'observed_connections': 3,
              'observed_endpoints': list(endpoints), 'issues': list(issues),
              'components': {'tun_coverage': 20}, 'time': '2026-11-16 17:36:38+0800'}
    if reputation is not None:
        report['reputation'] = reputation
    return report


def verified(entry):
    return {'status': 'partial', 'ip_reports': [entry], 'warnings': [],
            'probe': {'status': 'verified', 'observed_stable': True, 'sample_count': 3, 'elapsed_seconds': 3.2,
                      'samples': [{'status': 'verified'}] * 3}}


def plain(view, columns):
    return panels.render(panels.layout(view, columns), colored=False)


class Verdicts(unittest.TestCase):
    def test_first_line_states_the_conclusion(self):
        cases = [
            (route(reputation=verified(item())), '线路正常', 'vok'),
            (route(reputation=verified(item(95))), '有风险', 'vbad'),
            (route(endpoints=('DIRECT',), issues=['x: direct']), '有风险', 'vbad'),
            (route(endpoints=('Other',), issues=['x: Other; expected endpoint Node']), '节点不同', 'vwarn'),
            (route(reputation={'status': 'unknown', 'ip_reports': [],
                               'warnings': ['Exit probe is not fully route-verified; x']}), '出口未确认', 'vwarn'),
            (dict(route(), score=None, observed_connections=0, observed_endpoints=[]), '证据不足', 'vwarn'),
        ]
        for report, label, tone in cases:
            view = views.route_view(report)
            self.assertEqual(view['verdict'], (label, tone), report)
            self.assertIn(label, plain(view, 80)[0])

    def test_switched_node_with_same_exit_reads_as_normal(self):
        report = route(endpoints=('Other',), reputation=verified(item()))
        report['exit'] = {'status': 'matches', 'baseline_ips': [IP], 'current_ips': [IP], 'probed_node': 'Other'}
        view = views.route_view(report)
        self.assertEqual(view['verdict'], ('线路正常', 'vok'))
        self.assertIn('换了节点，出口没变', view['why'])
        report['exit'] = dict(report['exit'], status='changed', current_ips=['9.9.9.9'])
        self.assertEqual(views.route_view(report)['verdict'], ('出口变了', 'vbad'))

    def test_risky_source_turns_only_the_source_box_red(self):
        view = views.route_view(route(reputation=verified(item(95))))
        self.assertTrue(view['alert'])
        text = '\n'.join(plain(view, 80))
        self.assertIn('95 欺诈分', text)
        self.assertIn('D · 风险信号很强', text)
        self.assertFalse(views.route_view(route(reputation=verified(item())))['alert'])

    def test_machine_ip_never_claims_to_be_claude_exit(self):
        text = '\n'.join(plain(views.ip_view({'kind': 'machine_ip', 'ip_reports': [item()]}), 80))
        self.assertIn('非 Claude 实际出口', text)
        self.assertNotIn('当前线路', text)


class Layout(unittest.TestCase):
    def test_every_width_fits_and_wide_puts_exit_beside_route(self):
        view = views.route_view(route(reputation=verified(item(70))), interactive=True)
        for columns in (30, 40, 60, 79, 80, 120):
            lines = plain(view, columns)
            self.assertTrue(all(panels.cw(line) <= columns for line in lines), columns)
        wide, narrow = plain(view, 80), plain(view, 79)
        self.assertTrue(any('出口身份' in line and '当前线路' in line for line in wide))
        self.assertFalse(any('出口身份' in line and '当前线路' in line for line in narrow))
        self.assertLessEqual(len(wide), 24)

    def test_remote_strings_cannot_emit_controls(self):
        entry = item()
        entry['providers'][0]['network']['asn_label'] = '\x1b[2JEVIL'
        text = '\n'.join(plain(views.route_view(route(reputation=verified(entry))), 80))
        self.assertNotIn('\x1b', text)


class Progress(unittest.TestCase):
    def test_lookup_reports_each_source_in_order(self):
        events = []
        previous = set_progress(lambda stage, info: events.append((stage, info.get('provider'))))
        try:
            with patch('ip_reputation.fetch_json', return_value=(ipapi(), None)):
                lookup_reputation([IP], None, credentials={})
        finally:
            set_progress(previous)
        self.assertEqual([e for e in events if e[0] == 'source'],
                         [('source', 'ipapi.is'), ('source', 'scamalytics'), ('source', 'abuseipdb')])

    def test_running_view_only_shows_steps_that_happened(self):
        build = views.progress_view('route', 'Node')
        state = {'events': [('probe', {'index': 2, 'total': 3})]}
        view = build(state, '⠋', 1.5)
        text = '\n'.join(plain(view, 80))
        self.assertIn('第 2/3 次', text)
        self.assertIn('排队', text)
        self.assertNotIn('已完成', text)
        state['events'] += [('source', {'provider': 'ipapi.is'})]
        text = '\n'.join(plain(build(state, '⠋', 2.0), 80))
        self.assertIn('查询中', text)
        self.assertIn('回显 3/3', text)

    def test_live_progress_is_silent_without_a_terminal(self):
        output = io.StringIO()
        with patch('sys.stdout', output), patch.dict(os.environ, {'TERM': 'xterm'}):
            with panels.Live(views.progress_view('machine')) as live:
                live.event('echo', {})
        self.assertEqual(output.getvalue(), '')


if __name__ == '__main__':
    unittest.main()
