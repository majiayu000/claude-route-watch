"""Native macOS front end. The optional webview dependency is loaded only on launch."""
from copy import deepcopy
import json
import importlib.metadata
import os
from pathlib import Path
import tempfile
import threading
import time
import sys

from claude_route_watch import analyze, belongs_to_claude, notify, request
from exit_probe import utc_now
from ip_reputation import collect_reputation

CREDENTIAL_NAMES = ('IPAPI_IS_KEY', 'SCAMALYTICS_USERNAME', 'SCAMALYTICS_KEY', 'SCAMALYTICS_REGION', 'ABUSEIPDB_KEY')


class DesktopState:
    def __init__(self, settings_path=None, reader=request, collector=collect_reputation, notifier=notify):
        self._path = Path(settings_path) if settings_path else Path.home() / 'Library/Application Support/Claude Route Watch/settings.json'
        self._reader, self._collector, self._notifier = reader, collector, notifier
        self._lock = threading.RLock()
        self._closed = threading.Event()
        self._expected, self._monitoring, self._notifications = None, False, True
        self._settings_error = None
        try:
            saved = json.loads(self._path.read_text()) if self._path.exists() else {}
            if not isinstance(saved, dict):
                raise ValueError('Invalid preferences')
            self._expected = saved.get('expected') if isinstance(saved.get('expected'), str) else None
            if self._expected and self._expected.upper() in ('DIRECT', 'REJECT', 'REJECT-DROP'):
                self._expected = None
                raise ValueError('Invalid saved endpoint')
            self._monitoring = saved.get('monitoring') is True and bool(self._expected)
            self._notifications = saved.get('notifications', True) is True
        except (OSError, ValueError):
            self._settings_error = '上次的设置无法读取。请重新选择线路后开始监测，原文件暂未改写。'
        self._credentials = {key: os.environ[key] for key in CREDENTIAL_NAMES if os.environ.get(key)}
        self._nodes, self._observed = [], []
        self._proxy, self._connected, self._error = None, False, None
        self._report, self._ip_report = None, None
        self._ip_enabled, self._ip_busy = False, False
        self._cache, self._previous_ips = {}, None
        self._revision, self._next_ip_check = 0, 0
        self._checked_at, self._last_notice = None, None
        self._notification_error = None

    def _save(self, expected, monitoring, notifications):
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix='.settings-', dir=self._path.parent)
        try:
            with os.fdopen(fd, 'w') as stream:
                json.dump({'expected': expected, 'monitoring': monitoring, 'notifications': notifications}, stream)
            os.replace(name, self._path)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    def _status(self):
        with self._lock:
            return deepcopy({
                'connected': self._connected, 'error': self._error, 'settings_error': self._settings_error,
                'notification_error': self._notification_error,
                'nodes': self._nodes, 'observed_endpoints': self._observed,
                'suggested': self._observed[0] if len(self._observed) == 1 and self._observed[0] in self._nodes else None,
                'expected': self._expected, 'monitoring': self._monitoring, 'notifications': self._notifications,
                'proxy_available': self._proxy is not None, 'checked_at': self._checked_at,
                'route': self._report, 'ip_enabled': self._ip_enabled, 'ip_busy': self._ip_busy, 'reputation': self._ip_report,
                'credentials_available': {'ipapi.is': bool(self._credentials.get('IPAPI_IS_KEY')),
                                          'scamalytics': bool(self._credentials.get('SCAMALYTICS_USERNAME') and self._credentials.get('SCAMALYTICS_KEY')),
                                          'abuseipdb': bool(self._credentials.get('ABUSEIPDB_KEY'))},
                'scamalytics_region': self._credentials.get('SCAMALYTICS_REGION', 'us'),
            })

    def _begin(self, expected):
        with self._lock:
            if not self._connected or expected not in self._nodes:
                return {'ok': False, 'message': '请先打开 Clash，再从列表中选择一条可用代理线路。'}
            try:
                self._save(expected, True, self._notifications)
            except OSError:
                return {'ok': False, 'message': '无法保存设置，请检查应用支持目录的写入权限。'}
            self._expected, self._monitoring = expected, True
            self._settings_error = None
            self._revision += 1
            self._report = self._ip_report = None
            self._previous_ips, self._last_notice, self._next_ip_check = None, None, 0
        return {'ok': True, 'message': '已记住这条预期线路，正在监测。'}

    def _pause(self):
        with self._lock:
            try:
                self._save(self._expected, False, self._notifications)
            except OSError:
                return {'ok': False, 'message': '暂停设置无法保存；本次监测尚未停止。'}
            self._monitoring, self._ip_enabled = False, False
            self._revision += 1
            self._report = self._ip_report = None
            self._last_notice = None
        return {'ok': True, 'message': '已暂停。不会安排新的 IP 查询。'}

    def _set_ip(self, enabled):
        if not isinstance(enabled, bool):
            return {'ok': False, 'message': 'IP 检查设置无效。'}
        with self._lock:
            if enabled and (not self._monitoring or not self._proxy):
                return {'ok': False, 'message': '请先开始监测，并在 Clash 中开启 HTTP 或 Mixed 代理端口。'}
            self._ip_enabled = enabled
            self._revision += 1
            self._report = None
            self._ip_report = None
            self._next_ip_check = 0
            self._last_notice = None
        return {'ok': True, 'message': '已开启 IP 检查，第三方服务会收到探测出口 IP。' if enabled else '已关闭 IP 检查，正在进行的查询会结束。'}

    def _set_notifications(self, enabled):
        if not isinstance(enabled, bool):
            return {'ok': False, 'message': '通知设置无效。'}
        with self._lock:
            try:
                self._save(self._expected, self._monitoring, enabled)
            except OSError:
                return {'ok': False, 'message': '无法保存通知设置。'}
            self._notifications = enabled
            if not enabled:
                self._notification_error = None
        return {'ok': True, 'message': '异常时会请求 macOS 通知。' if enabled else '已关闭系统通知。'}

    def _set_credentials(self, values):
        if not isinstance(values, dict) or any(key not in CREDENTIAL_NAMES or not isinstance(value, str) or len(value) > 8192 for key, value in values.items()):
            return {'ok': False, 'message': '凭据格式无效。'}
        if values.get('SCAMALYTICS_REGION', 'us') not in ('us', 'eu'):
            return {'ok': False, 'message': '请选择 Scamalytics 账号所在的 US 或 EU 节点。'}
        with self._lock:
            self._credentials.update({key: value for key, value in values.items() if value})
            self._cache = {}
            self._revision += 1
            self._ip_report, self._next_ip_check = None, 0
        return {'ok': True, 'message': '本次已配置。凭据只留在内存，关闭 App 后清除。'}

    def _clear_credentials(self):
        with self._lock:
            self._credentials, self._cache = {}, {}
            self._revision += 1
            self._ip_report, self._next_ip_check = None, 0
        return {'ok': True, 'message': '已清除用于后续检查的凭据；正在进行的查询会结束。'}

    def _sample_once(self):
        with self._lock:
            expected, active, revision = self._expected, self._monitoring, self._revision
        try:
            config, connections, proxies = self._reader('/configs'), self._reader('/connections'), self._reader('/proxies')['proxies']
            nodes = sorted(name for name, value in proxies.items() if 'all' not in value and
                           value.get('type', '').lower() not in ('direct', 'reject', 'rejectdrop', 'pass', 'compatible'))
            observed = sorted({row['chains'][0] for row in connections['connections'] if row.get('chains') and belongs_to_claude(row['metadata'])})
            port = config.get('mixed-port') or config.get('port')
            proxy = f'http://127.0.0.1:{port}' if isinstance(port, int) and not isinstance(port, bool) and 0 < port < 65536 else None
            report = analyze(config, connections, expected) if active else None
            connected, error = True, None
        except Exception:
            nodes, observed, proxy, report, connected = [], [], None, None, False
            error = '暂时无法读取 Clash。请先打开 Clash Verge，应用会自动重试。'
        with self._lock:
            self._nodes, self._observed, self._proxy = nodes, observed, proxy
            self._connected, self._error, self._checked_at = connected, error, utc_now()
            if revision != self._revision or self._closed.is_set():
                return
            self._report = report
            if active and self._ip_enabled and proxy and not self._ip_busy and time.monotonic() >= self._next_ip_check:
                self._ip_busy = True
                threading.Thread(target=self._check_ip, args=(revision, proxy, expected, dict(self._credentials), self._cache, self._previous_ips), daemon=True).start()
            if not active:
                return
            warnings = [error] if error else list(report.get('issues', []))
            if self._ip_enabled and self._ip_report:
                warnings += self._ip_report.get('warnings', [])
                if self._ip_report.get('status') in ('partial', 'unknown'):
                    warnings.append('IP 信誉证据不完整，请查看界面中的未检测项目。')
            unknown = report is not None and report.get('score') is None
            notice = (tuple(warnings), unknown)
            changed = notice != self._last_notice
            recovering = self._last_notice is not None and (bool(self._last_notice[0]) or self._last_notice[1]) and not warnings and not unknown
            self._last_notice = notice
            notifications = self._notifications
        if changed and notifications and (warnings or unknown or recovering):
            message = '；'.join(warnings)[:600] if warnings else ('暂无 Claude 活跃连接，等待新的连接。' if unknown else '当前观察已恢复符合预期。')
            try:
                self._notifier('Claude 线路观察', message)
                with self._lock:
                    self._notification_error = None
            except Exception:
                with self._lock:
                    self._notification_error = '系统通知提交失败，界面仍会显示变化。请检查 macOS 通知设置。'

    def _check_ip(self, revision, proxy, expected, credentials, cache, previous_ips):
        try:
            result = self._collector(proxy, expected, lambda: self._reader('/connections'), cache=cache,
                                     previous_ips=previous_ips, credentials=credentials)
        except Exception:
            result = {'status': 'unknown', 'ip_reports': [], 'warnings': ['IP 检查暂时失败，无法据此判断信誉。']}
        with self._lock:
            self._ip_busy = False
            if revision != self._revision or not self._monitoring or not self._ip_enabled or self._closed.is_set():
                return
            self._ip_report = result
            self._next_ip_check = time.monotonic() + 300
            if result.get('probe', {}).get('status') == 'verified':
                self._previous_ips = result['probe']['ips']

    def _run(self):
        while not self._closed.is_set():
            self._sample_once()
            self._closed.wait(2)

    def _close(self):
        self._closed.set()


class DesktopAPI:
    """Only these narrow methods are exposed to the bundled, offline page."""
    def __init__(self, state):
        self._state = state
        self._window = None

    def get_status(self):
        return self._state._status()

    def begin(self, expected):
        return self._state._begin(expected)

    def pause(self):
        return self._state._pause()

    def set_ip(self, enabled):
        return self._state._set_ip(enabled)

    def set_notifications(self, enabled):
        return self._state._set_notifications(enabled)

    def save_credentials(self, values):
        return self._state._set_credentials(values)

    def clear_credentials(self):
        return self._state._clear_credentials()

    def test_notification(self):
        try:
            self._state._notifier('Claude Route Watch · 测试', '这是一条测试通知，不代表线路或账号异常。')
            return {'ok': True, 'message': '已提交测试通知，请在通知中心确认是否显示。'}
        except Exception:
            return {'ok': False, 'message': '通知提交失败，请检查系统通知设置。'}

    def quit(self):
        self._state._close()
        if self._window is not None:
            self._window.destroy()
        return {'ok': True}


def main():
    import webview
    state = DesktopState()
    api = DesktopAPI(state)
    if getattr(sys, 'frozen', False):
        page = Path(__file__).parent / 'docs/app.html'
    else:
        distribution = importlib.metadata.distribution('claude-route-watch')
        asset = next(item for item in distribution.files if item.parts[-2:] == ('docs', 'app.html'))
        page = distribution.locate_file(asset)
    html = page.read_text()
    window = webview.create_window('Claude Route Watch', html=html, js_api=api, width=1040, height=800,
                                   min_size=(760, 620), text_select=True, background_color='#f5f6f8')
    api._window = window
    try:
        threading.Thread(target=state._run, daemon=True).start()
        webview.start(gui='cocoa', debug=False, private_mode=True)
    finally:
        state._close()


if __name__ == '__main__':
    main()
