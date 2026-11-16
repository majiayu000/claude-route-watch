"""Turn check reports (and live progress events) into dashboard views for panels.py."""
from datetime import datetime
import re

from ip_reputation import DOCS, metric_level
from panels import col, kv, seg

STATE = {'ok': ('已完成', 'ok'), 'partial': ('部分可用', 'warn'), 'skipped': ('未配置', 'dim'),
         'rate_limited': ('已限流', 'warn'), 'error': ('失败', 'bad'), 'unknown': ('未知', 'warn'),
         'queued': ('排队', 'dim'), 'running': ('查询中', 'acc')}
WARNINGS = {'Exit IP changed across fresh probe connections': '多次回显的 IP 不一致',
            'Observed exit IP set changed since the previous verified check': '出口 IP 和上次不同',
            'Exit probe is not fully route-verified': '回显没能确认走了预期节点',
            'Controller unavailable': '读不到 Clash，没有回显出口'}
SCORE_NAMES = {'scamalytics': '欺诈分', 'abuseipdb': '滥用置信'}
VERDICT_TONE = {'ok': 'vok', 'warn': 'vwarn', 'bad': 'vbad'}


def warning_text(text):
    return next((value for key, value in WARNINGS.items() if text.startswith(key)), '有待核对的信号，见详情')


def short_time(stamp):
    """Local HH:MM:SS for UTC ISO stamps (IP checks) and local strftime stamps (route checks)."""
    try:
        return datetime.fromisoformat(stamp).astimezone().strftime('%H:%M:%S')
    except (TypeError, ValueError):
        match = re.search(r'(\d{2}:\d{2}:\d{2})', stamp or '')
        return match.group(1) if match else ''


# ---------- exit identity ----------

def first(providers, group, *keys):
    return next((source.get(group, {}).get(key) for source in providers for key in keys
                 if source.get(group, {}).get(key)), None)


def place(providers):
    geo = next((source['geo'] for source in providers if any(source.get('geo', {}).values())), {})
    parts = [geo.get('country_name') or geo.get('country_code'), geo.get('region'), geo.get('city')]
    text = ' · '.join(str(part) for part in parts if part)
    if len(text) > 28:  # keep country and city inside the half-width box; details keep the region
        text = ' · '.join(str(part) for part in (parts[0], parts[2]) if part)
    return text or '地区未知'


def kind(providers):
    marks, seen = [], False
    for key, title in (('datacenter', '机房'), ('vpn', 'VPN'), ('proxy', '代理'), ('tor', 'Tor')):
        values = {source['provider']: source.get('flags', {}).get(key) for source in providers}
        seen = seen or any(value is not None for value in values.values())
        hits = [name for name, value in values.items() if value is True]
        if hits:
            marks.append(title + '（' + '、'.join(hits) + '）')
    if marks:
        return [seg(' · '.join(marks), 'warn')]
    return [seg('未标机房 / VPN / 代理' if seen else '未知（字段缺失）', 'dim')]


def identity_rows(report, item):
    probe = report.get('probe', {})
    if not item:
        reason = probe.get('reason') or ('回显没能确认线路' if probe.get('status') else '没有回显')
        return [kv('IP', [seg('未确认', 'warnb')]), kv('原因', reason, 'dim'),
                kv('', '未知不表示 IP 干净', 'dim')]
    providers = item['providers']
    network = first(providers, 'network', 'asn_label', 'asn_organization', 'company', 'isp')
    rows = [kv('IP', item['ip'], 'b'), kv('地区', place(providers)), kv('网络', network or '未知'),
            kv('类型', kind(providers))]
    if report.get('kind') == 'machine_ip':
        rows.append(kv('采样', '直连回显 1 次', 'dim'))
    elif probe.get('samples'):
        good = sum(sample.get('status') == 'verified' for sample in probe['samples'])
        stable = probe.get('observed_stable')
        text = f"{good}/{probe.get('sample_count', len(probe['samples']))} 次"
        text += ' 同一 IP' if stable else ' · IP 不一致' if stable is False else ''
        if probe.get('elapsed_seconds') is not None:
            text += f" · {probe['elapsed_seconds']:.1f} s"
        rows.append(kv('采样', text, 'dim' if stable else 'warn'))
    if len(report.get('ip_reports', [])) > 1:
        rows.append(kv('', f"另有 {len(report['ip_reports']) - 1} 个 IP，见详情", 'warn'))
    return rows


# ---------- sources ----------

def source_signal(source, alert):
    for metric in source.get('scores', []):
        level = metric_level(source['provider'], metric)
        if level is None:
            continue
        value = metric['value']
        tone = 'bad' if level >= 2 else 'warn' if level else 'ok'
        filled = round(value / 10)
        line = [('▰' * filled, tone), ('▱' * (10 - filled), 'dim'),
                seg(f"  {value} {SCORE_NAMES.get(source['provider'], metric['name'])}", tone + ('b' if level >= 2 else ''))]
        reports = source.get('details', {}).get('total_reports')
        if reports:
            line.append(seg(f'  近期 {reports} 次举报', 'dim'))
        return line
    state = source['status']
    if state == 'skipped':
        names = source.get('required_environment') or []
        return [seg('需 ' + ' / '.join(names) if names else '未配置', 'dim')]
    if state == 'rate_limited':
        wait = source.get('retry_after_seconds')
        return [seg(f'约 {wait} 秒后再试' if wait else '等配额恢复再试', 'dim')]
    if state == 'error':
        return [seg('查询失败，未计入结果', 'dim')]
    flags = source.get('flags', {})
    if any(flags.get(key) is True for key in ('abuser', 'external_blacklist')):
        return [seg('有滥用 / 黑名单标记', 'badb')]
    if state == 'partial':
        return [seg('地区和网络有，风险字段缺', 'dim')]
    return [seg('无风险标记', 'dim')]


def source_rows(item, alert):
    rows = []
    for source in item['providers']:
        label, tone = STATE.get(source['status'], (source['status'], 'warn'))
        skipped = source['status'] == 'skipped'
        rows.append([col(source['provider'], 13, 'dim' if skipped else 'b'), col(label, 10, tone)]
                    + source_signal(source, alert))
    return rows


def grade_line(item):
    rating = item['rating']
    grade = rating['grade']
    if grade is None:
        if rating['reasons']:
            return kv('等级', [seg('暂不评级', 'warnb'), seg('  但已有风险信号，按 d 看依据', 'badb')])
        return kv('等级', [seg('暂不评级', 'warnb'),
                         seg(f"  评级要三家来源齐全，现在 {rating['ready_sources']}/{rating['required_sources']}", 'dim')])
    tone = 'okb' if grade == 'A' else 'warnb' if grade == 'B' else 'badb'
    return kv('等级', [seg(grade + ' · ' + rating['label'], tone), seg('  取最强一家，不平均', 'dim')])


def steps_done(report, item):
    line = []
    if report.get('kind') != 'machine_ip':
        line += [('✓', 'ok'), (' 读 Clash  ', '')]
    probe = report.get('probe', {})
    if probe.get('samples'):
        good = sum(sample.get('status') == 'verified' for sample in probe['samples'])
        mark = ('✓', 'ok') if good == len(probe['samples']) else ('!', 'warn')
        line += [mark, (f" 回显 {good}/{len(probe['samples'])}  ", '')]
    elif probe.get('status') == 'observed':
        line += [('✓', 'ok'), (' 回显  ', '')]
    for source in (item or {}).get('providers', []):
        mark = {'skipped': ('○', 'dim'), 'error': ('✗', 'bad'), 'rate_limited': ('!', 'warn')}.get(
            source['status'], ('✓', 'ok'))
        line += [mark, seg(' ' + source['provider'] + '  ', 'dim' if source['status'] == 'skipped' else '')]
    return line


# ---------- whole views ----------

def reputation_verdict(report, item):
    if not item:
        return 'warn', '出口未确认', warning_text((report.get('warnings') or [''])[0]) if report.get('warnings') else '没拿到出口或信誉数据'
    grade = item['rating']['grade']
    if grade in ('C', 'D'):
        return 'bad', '有风险', f"IP 信誉 {grade} · {item['rating']['label']}"
    if report.get('warnings') and report.get('kind') != 'machine_ip':
        return 'warn', '需核对', warning_text(report['warnings'][0])
    if grade == 'B' or item.get('advisories'):
        return 'warn', '需核对', 'IP 信誉 ' + (grade or '暂不评级') + ' · 有待核对的信号'
    return 'ok', None, ('IP 信誉 A · ' + item['rating']['label']) if grade else '信誉暂不评级'


def ip_view(report, interactive=False):
    items = report.get('ip_reports', [])
    item = items[0] if items else None
    tone, label, why = reputation_verdict(report, item)
    scope = [kv('方式', '本机直连 · 不经 Clash'), kv('含义', [seg('本机出口，非 Claude 实际出口', 'warn')]),
             kv('代理', '忽略 HTTP 代理变量', 'dim'), kv('', 'VPN / TUN 仍可能改变出口', 'dim')]
    return {
        'verdict': (label or ('出口正常' if item and item['rating']['grade'] else '已查到出口'), VERDICT_TONE[tone]),
        'why': why,
        'right': short_time(report.get('checked_at')),
        'boxes': (('出口身份', identity_rows(report, item)), ('检测范围', scope)),
        'sources': source_rows(item, tone == 'bad') if item else [[seg('没有查询信誉来源：先要拿到出口 IP', 'dim')]],
        'grade': grade_line(item) if item else kv('等级', [seg('不评级', 'warnb')]),
        'alert': tone == 'bad', 'steps': steps_done(report, item),
        'note': 'A–D 是本工具的证据等级，不是封号概率',
        'keys': [('Enter', '返回'), ('d', '来源详情'), ('r', '重查'), ('0', '退出')] if interactive else None,
    }


def exit_state(report):
    return (report.get('exit') or {}).get('status', 'unchecked')


def route_rows(report):
    expected = report.get('expected', '未选择')
    endpoints = report.get('observed_endpoints') or []
    state = exit_state(report)
    rows = [kv('预期', expected)]
    if not endpoints:
        rows.append(kv('实际', '没看到 Claude 连接', 'warn'))
    elif endpoints == [expected]:
        rows.append(kv('实际', [seg(expected), (' ✓', 'ok')]))
    elif any(name.upper() == 'DIRECT' for name in endpoints):
        rows.append(kv('实际', [seg(' / '.join(endpoints), 'badb')]))
    else:
        rows.append(kv('实际', [seg(' / '.join(endpoints), '' if state == 'matches' else 'warnb')]))
        rows.append(kv('', {'matches': '换了节点，出口没变 · 只记录',
                            'changed': '换了节点，出口 IP 也变了',
                            'unconfirmed': '换了节点；没有出口基准可比'}.get(
            state, '换了节点；出口没查，无法判断'), 'dim' if state == 'matches' else 'warn'))
    issues = [item for item in report.get('issues', []) if item not in report.get('node_changes', [])
              and not item.startswith('Exit IP changed')]
    count = report.get('observed_connections', 0)
    rows.append(kv('连接', f'Claude {count} 条' + (f' · 异常 {len(issues)} 项' if issues else ''),
                   'warn' if issues else ''))
    tun = (report.get('components') or {}).get('tun_coverage')
    if tun is not None:
        rows.append(kv('TUN', [seg('已覆盖', 'ok') if tun else seg('未开启，部分流量看不到', 'warn')]))
    return rows


def baseline_row(report):
    exit_info = report.get('exit') or {}
    state, baseline = exit_info.get('status'), exit_info.get('baseline_ips')
    if state == 'matches':
        return kv('基准', [seg('和基准相同', ''), (' ✓', 'ok')])
    if state == 'changed':
        return kv('基准', [seg(', '.join(baseline or []), 'badb'), seg(' → 已变', 'badb')])
    if baseline:
        return kv('基准', '本次出口，之后以它为准', 'dim')
    return None


def route_verdict(report, rep, item):
    endpoints = report.get('observed_endpoints') or []
    expected = report.get('expected')
    state = exit_state(report)
    moved = bool(endpoints) and endpoints != [expected]
    current = ', '.join((report.get('exit') or {}).get('current_ips') or [])
    if any(name.upper() == 'DIRECT' for name in endpoints):
        return 'bad', '有风险', 'Claude 有连接直连，没走代理'
    if state == 'changed':
        return 'bad', '出口变了', ', '.join(report['exit']['baseline_ips']) + ' → ' + current
    if report.get('score') is None:
        why = '没看到 Claude 连接，先发一次请求' if not report.get('observed_connections') and \
            not report.get('issues') else '读不到 Clash 或连接记录不完整'
        return 'warn', '证据不足', why
    if moved and state == 'unconfirmed':
        return 'warn', '节点不同', f'出口 {current}，请确认是不是你要的' if current else '没有基准可比'
    if moved and state != 'matches':
        return 'warn', '节点不同', '实际走 ' + ' / '.join(endpoints)
    if report.get('issues'):
        return 'warn', '线路不符', 'TUN 未开启'
    prefix = '换了节点，出口没变 · ' if moved else ''
    if rep is None:
        return 'ok', '线路正常', prefix + '出口未检查（菜单里选 y 才查）'
    if rep.get('status') == 'pending':
        return 'warn', '线路正常', prefix + '出口和信誉检查中'
    rtone, rlabel, rwhy = reputation_verdict(rep, item)
    stable = (rep.get('probe') or {}).get('observed_stable')
    if rtone == 'ok':
        return 'ok', '线路正常', prefix + ('出口稳定 · ' if stable and not moved else '') + rwhy
    return rtone, rlabel or '线路正常', rwhy


def route_view(report, interactive=False, watching=False):
    rep = report.get('reputation')
    item = None
    if rep is not None:
        items = rep.get('ip_reports', [])
        item = items[0] if items else None
    tone, label, why = route_verdict(report, rep, item)
    if rep is None:
        identity = [kv('IP', '未检查', 'dim'), kv('', '菜单里选 y 才会回显出口', 'dim')]
        sources = [[seg('没有查询信誉来源', 'dim')]]
        grade = kv('等级', '—', 'dim')
    elif rep.get('status') == 'pending':
        identity = [kv('IP', [seg('检查中…', 'acc')])]
        sources = [[seg('等待出口回显', 'dim')]]
        grade = kv('等级', '等来源返回后再评', 'dim')
    else:
        identity = identity_rows(rep, item)
        extra = baseline_row(report)
        if extra:
            identity.insert(1, extra)
        sources = source_rows(item, tone == 'bad') if item else [[seg('没有查询信誉来源：出口未确认', 'dim')]]
        grade = grade_line(item) if item else kv('等级', [seg('不评级', 'warnb')])
    keys = [('Ctrl-C', '停止观察')] if watching else \
        [('Enter', '返回'), ('r', '重查')] if interactive else None
    node = (report.get('exit') or {}).get('probed_node') or (rep or {}).get('probed_node')
    note = (f'回显经 Claude 当前节点 {node}' if node else '回显出口') + ' · 不是 Anthropic 所见 IP 的证明' if rep else \
        '仅含 Clash 可见连接 · 路由分不是 IP 信誉'
    if watching:
        note = '只在变化时刷新 · ' + note
    return {
        'verdict': (label, VERDICT_TONE[tone]), 'why': why, 'right': short_time(report.get('time')),
        'boxes': (('出口身份', identity), ('当前线路', route_rows(report))),
        'sources': sources, 'grade': grade, 'alert': bool(item and item['rating']['grade'] in ('C', 'D')),
        'steps': steps_done(rep or {}, item) if rep else None, 'note': note, 'keys': keys,
    }


# ---------- live progress ----------

def progress_view(kind, expected=None):
    """Build a function(state, spinner, elapsed) -> view from real progress events."""
    def build(state, spin, elapsed):
        probe, sources, stage = None, {}, '准备中'
        for name, info in state.get('events', []):
            if name == 'echo':
                stage = '回显本机出口'
            elif name == 'probe':
                probe = (info['index'], info['total'])
                stage = f"经 {info.get('node') or expected} 回显出口，第 {probe[0]}/{probe[1]} 次"
            elif name == 'source':
                sources[info['provider']] = 'running'
                stage = '查询 ' + info['provider']
            elif name == 'source_done':
                sources[info['provider']] = info['status']
        steps = [] if kind == 'machine' else [('✓', 'ok'), (' 读 Clash  ', '')]
        if kind == 'machine':
            steps += [(spin, 'acc'), (' 回显  ', 'acc')] if not sources else [('✓', 'ok'), (' 回显  ', '')]
        elif probe or sources:
            done = bool(sources)
            steps += [('✓', 'ok') if done else (spin, 'acc'),
                      (f" 回显 {probe[1] if done else probe[0]}/{probe[1]}  " if probe else ' 回显  ', '' if done else 'acc')]
        rows = []
        for provider in DOCS:
            state_name = sources.get(provider, 'queued')
            label, tone = STATE.get(state_name, (state_name, 'warn'))
            mark = {'queued': ('·', 'dim'), 'running': (spin, 'acc'), 'skipped': ('○', 'dim'),
                    'error': ('✗', 'bad')}.get(state_name, ('✓', 'ok'))
            steps += [mark, (' ' + provider + '  ', 'dim' if state_name in ('queued', 'skipped') else '')]
            rows.append([col(provider, 13, 'dim' if state_name in ('queued', 'skipped') else 'b'), col(label, 10, tone)])
        waiting = [kv('IP', [(spin + ' 等待回显…', 'acc')])] if not sources else [kv('IP', '已拿到，正在查来源', 'dim')]
        if probe and not sources:
            waiting.append(kv('采样', [('▰' * probe[0], 'acc'), ('▱' * (probe[1] - probe[0]), 'dim'),
                                       (f'  {probe[0]}/{probe[1]}', 'dim')]))
        right = (('预期', [seg(expected)]),) if expected else ()
        right_rows = [kv(k, v) for k, v in right] + ([kv('实际', '已读取，和出口一起显示', 'dim')] if expected else
                                                     [kv('方式', '本机直连 · 不经 Clash')])
        return {
            'verdict': ('检测中', 'vwarn'), 'why': stage, 'right': f'已用 {elapsed:.1f} s',
            'boxes': (('出口身份', waiting), ('当前线路' if expected else '检测范围', right_rows)),
            'sources': rows, 'grade': kv('等级', '等来源返回后再评', 'dim'),
            'steps': steps, 'running': True, 'keys': [('Ctrl-C', '停止')],
        }
    return build
