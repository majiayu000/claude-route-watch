"""Small terminal front end. No settings, uploads, services or UI dependencies."""
import http.client
import platform
import shutil
import sys
import unicodedata

from exit_probe import FetchError, PROBE_URL, fetch_json, progress, set_progress, utc_now
from ip_reputation import lookup_reputation, public_ip
import panels
import views


def display(value):
    """Keep remote names and source labels from emitting terminal control sequences."""
    return ''.join(char if char.isprintable() else ' ' for char in str(value))


def check_ip(*, credentials=None):
    """Observe this machine's default-route echo IP; never claim Claude attribution."""
    report = {'kind': 'machine_ip', 'status': 'unknown', 'checked_at': utc_now(),
              'transport': 'direct', 'ip_reports': [], 'warnings': [],
              'scope': 'This machine to the echo service; not Claude or Anthropic-side IP proof'}
    try:
        progress('echo')
        data, _ = fetch_json(PROBE_URL, None, headers={'Cache-Control': 'no-cache'})
        ip = public_ip(data.get('ip'))
    except FetchError as error:
        report['probe'] = {'status': 'unknown', 'reason': error.reason,
                           'http_status': error.http_status}
    except (OSError, ValueError, TypeError, http.client.HTTPException) as error:
        report['probe'] = {'status': 'unknown', 'reason': 'echo_unavailable',
                           'error_type': type(error).__name__}
    else:
        report['probe'] = {'status': 'observed', 'ip': ip, 'service': PROBE_URL,
                           'checked_at': utc_now()}
        result = lookup_reputation([ip], None, credentials=credentials)
        report.update(result)
    return report


def reputation_exit_code(report):
    if report.get('status') != 'complete':
        return 2
    return 1 if report.get('warnings') else 0


def paint(text, style):
    if panels.color_enabled():
        return f'\033[{style}m{text}\033[0m'
    return text


def cell_width(text):
    return sum(0 if unicodedata.combining(c) else 2 if unicodedata.east_asian_width(c) in ('W', 'F') else 1
               for c in text)


def clipped(value, width):
    text = display(value)
    if cell_width(text) <= width:
        return text
    result = ''
    for char in text:
        if cell_width(result + char) > width - 1:
            break
        result += char
    return result + '…'


def screen_width():
    return max(24, min(80, shutil.get_terminal_size((80, 24)).columns - 2))


def line(value='', style=None):
    text = clipped(value, screen_width())
    print(paint(text, style) if style else text)


def heading(title):
    print()
    line('CLAUDE ROUTE WATCH  /  ' + title, '1;36')
    line('━' * screen_width(), '36')


def print_ip_report(report, interactive=False):
    """One-screen dashboard; original evidence is available through explicit details."""
    print()
    panels.show(views.ip_view(report, interactive))


def print_ip_details(report):
    print('\n── IP 与信誉 ──')
    if report.get('kind') == 'machine_ip':
        print('范围：当前机器到回显服务的出口；不代表 Claude 的实际出口。')
        print('连接方式：不使用环境变量中的 HTTP 代理；系统 VPN/TUN 仍可能影响出口。')
    else:
        print('范围：经预期节点的回显与信誉查询；不是 Anthropic 所见 IP 的证明。')
    probe = report.get('probe', {})
    if probe.get('ip'):
        print('公网 IP：' + display(probe['ip']))
    if not report.get('ip_reports'):
        print('证据不足：未得到可归因的出口或可用的信誉数据。')
        if probe.get('reason'):
            print('探测状态：' + display(probe['reason']))
        print('请检查网络、证书和 Clash 状态后重试；未知不表示 IP 干净。')
    for item in report.get('ip_reports', []):
        print('\nIP：' + display(item['ip']))
        providers = item['providers']
        usable = sum(source['status'] in ('ok', 'partial') for source in providers)
        print(f'证据：{usable}/{len(providers)} 个来源提供数据')
        rating = item['rating']
        print('IP 信誉等级：' + (rating['grade'] + ' · ' if rating['grade'] else '') + display(rating['label']))
        print(f"评级所需主字段：{rating['ready_sources']}/{rating['required_sources']} 个来源齐全 · 规则 v{rating['version']}")
        if rating['incomplete_sources']:
            print('尚缺完整证据：' + display('、'.join(rating['incomplete_sources'])))
        for reason in rating['reasons']:
            print('  评级依据：' + display(reason))
        for source in providers:
            state = source['status']
            label = {'ok': '已完成', 'partial': '部分字段缺失', 'skipped': '未配置，未检测',
                     'rate_limited': '已限流', 'error': '查询失败', 'unknown': '未知'}.get(state, state)
            print('  ' + display(source['provider']) + '：' + display(label))
            geo, network = source.get('geo', {}), source.get('network', {})
            location = ' / '.join(str(x) for x in (geo.get('country_name') or geo.get('country_code'),
                                                   geo.get('region'), geo.get('city')) if x)
            if location:
                print('    地区：' + display(location))
            owner = network.get('asn_organization') or network.get('company') or network.get('asn_label')
            if owner:
                print('    网络：' + display(owner))
            if network.get('asn') is not None:
                print('    ASN：AS' + display(network['asn']))
            for key, title in (('datacenter', '机房'), ('vpn', 'VPN'), ('proxy', '代理'),
                               ('tor', 'Tor'), ('abuser', '曾被标记滥用')):
                value = source.get('flags', {}).get(key)
                if state in ('ok', 'partial'):
                    print(f'    {title}：' + ('未知' if value is None else ('是' if value else '否')))
            for metric in source.get('scores', []):
                if metric.get('value') is not None:
                    print('    ' + display(metric['name']) + '：' + display(metric['value']))
                    print('      范围：' + display(metric.get('scope', '该来源的 IP 指标')))
            if state == 'skipped':
                print('    基础检测无需密钥；高级来源可选配置现有环境变量，见 README。')
            elif state == 'rate_limited':
                print('    请等待来源配额恢复，避免反复重试。')
            elif state == 'error':
                print('    未计入成功结果，请检查网络或该来源的认证状态。')
        if item.get('country_comparison', {}).get('status') == 'disagreement':
            print('  注意：来源对国家的判断不一致，请逐来源核对。')
    for warning in report.get('warnings', []):
        print('注意：' + display(warning))
    print('查询时间：' + display(report.get('checked_at', '未知')))
    print('A–D 是本站规则下的证据信号等级；不是综合安全分、网速等级或封号概率。', flush=True)


def print_route_report(report):
    print()
    panels.show(views.route_view(report))


def with_progress(build, task):
    """Run task() while a live dashboard follows its real progress events (TTY only)."""
    with panels.Live(build) as live:
        previous = set_progress(live.event if live.thread else None)
        try:
            return task()
        finally:
            set_progress(previous)


def inspect_ip_report(report):
    """Returns True for the menu, False to exit, 'again' to re-run the same check."""
    print_ip_report(report, interactive=True)
    while True:
        value = input('> ').strip().lower()
        if value == 'd':
            print_ip_details(report)
            keys = panels.keys_line([('Enter', '返回'), ('r', '重查'), ('0', '退出')])
            print(panels.render([keys], panels.color_enabled())[0])
        elif value == '0':
            return False
        elif value == 'r':
            return 'again'
        elif not value:
            return True


def choose(prompt, options):
    while True:
        for number, option in enumerate(options, 1):
            line(f'  {number}. {display(option)}', '36')
        line('  0. 返回 / 退出', '90')
        value = input(prompt).strip()
        if value == '0':
            return None
        if value.isascii() and value.isdigit() and 1 <= int(value) <= len(options):
            return int(value) - 1
        print('请输入列表中的数字。')


def route_check(config_path=None, socket_path=None, watch=False):
    from claude_route_watch import belongs_to_claude, main, request
    try:
        config = request('/configs', config_path, socket_path)
        proxies = request('/proxies', config_path, socket_path)['proxies']
        connections = request('/connections', config_path, socket_path)['connections']
        nodes = sorted(name for name, value in proxies.items() if 'all' not in value and
                       value.get('type', '').lower() not in ('direct', 'reject', 'rejectdrop', 'pass', 'compatible'))
        observed = {row['chains'][0] for row in connections
                    if row.get('chains') and belongs_to_claude(row['metadata'])}
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RuntimeError, http.client.HTTPException):
        print('无法读取 Clash。请打开 Clash Verge；其他 Unix Mihomo 可用 --menu --socket 路径 --config 路径。')
        print('控制器密钥沿用现有配置或 MIHOMO_SECRET，程序不会改写配置。')
        return 2
    if not nodes:
        print('没有可选择的最终代理节点，请先检查 Clash 配置。')
        return 2
    print('\n请明确选择预期节点；当前观察到的节点仅供参考，不会自动当成正确答案。')
    labels = [name + ('（当前观察到 Claude 使用）' if name in observed else '') for name in nodes]
    selected = choose('预期节点编号：', labels)
    if selected is None:
        return 0
    args = ['--expect', nodes[selected]]
    if config_path:
        args += ['--config', config_path]
    if socket_path:
        args += ['--socket', socket_path]
    port = config.get('mixed-port') or config.get('port')
    if isinstance(port, int) and not isinstance(port, bool) and 0 < port < 65536:
        print('可通过发现的本地代理查询出口和 IP 信誉；这会连接 ipify 与已配置的信誉服务。')
        if input('同时检查 IP？[y/N]：').strip().lower() == 'y':
            args += ['--reputation', '--proxy', f'http://127.0.0.1:{port}']
    if watch:
        args += ['--watch']
        region = panels.Region()
        print()
        return main(args, report_output=lambda report: region.draw(views.route_view(report, watching=True)))
    while True:
        reports = []
        result = with_progress(views.progress_view('route', nodes[selected]),
                               lambda: main(args, report_output=reports.append))
        print()
        for report in reports:
            panels.show(views.route_view(report, interactive=True))
        if input('> ').strip().lower() != 'r':
            return result


def menu(config_path=None, socket_path=None):
    if not sys.stdin.isatty():
        print('菜单需要交互终端。单次 IP 检查用 --ip，机器读取用 --ip --json；帮助用 --help。', file=sys.stderr)
        return 2
    heading('终端检查')
    line(platform.system() + ' / ' + platform.machine() + '  ·  选择项目开始检查', '90')
    try:
        while True:
            selected = choose('\n请选择：', ['检查当前机器的公网 IP 与信誉（无需 Clash）',
                                             '检查 Claude 在 Clash 中的实际线路', '持续观察 Claude 线路变化'])
            if selected is None:
                return 0
            if selected == 0:
                line('正在查询 IP 与信誉来源…（会连接外部查询服务）', '36')
                while True:
                    report = with_progress(views.progress_view('machine'), check_ip)
                    choice = inspect_ip_report(report)
                    if choice != 'again':
                        break
                if not choice:
                    return 0
            else:
                route_check(config_path, socket_path, watch=selected == 2)
    except (EOFError, KeyboardInterrupt):
        print('\n已退出。')
        return 0
