"""Build the dependency-free terminal archive with the Python standard library."""
import base64
import hashlib
from pathlib import Path
import shutil
import shlex
import tempfile
import zipapp
import zipfile

root = Path(__file__).resolve().parent.parent
dist = root / 'dist'
dist.mkdir(exist_ok=True)
with tempfile.TemporaryDirectory(prefix='route-watch-build-') as staging:
    source = Path(staging)
    for name in ('claude_route_watch', 'exit_probe', 'ip_reputation', 'panels', 'terminal', 'views'):
        shutil.copyfile(root / (name + '.py'), source / (name + '.py'))
    (source / '__main__.py').write_text(
        'from claude_route_watch import main\n'
        'try:\n'
        '    raise SystemExit(main())\n'
        'except KeyboardInterrupt:\n'
        '    pass\n')
    app = dist / 'claude-route-watch.pyz'
    zipapp.create_archive(source, app, interpreter='/usr/bin/env python3',
                          compressed=True)
launcher = dist / 'claude-route-watch.sh'
bootstrap = '''import base64, pathlib, subprocess, sys, tempfile
if sys.version_info < (3, 10):
    print('需要 Python 3.10 或更新版本；程序不会自动修改系统。', file=sys.stderr)
    raise SystemExit(2)
with tempfile.TemporaryDirectory(prefix='claude-route-watch-') as directory:
    app = pathlib.Path(directory) / 'watch.pyz'
    app.write_bytes(base64.b64decode(PAYLOAD))
    terminal = None
    if len(sys.argv) == 1 and not sys.stdin.isatty():
        try:
            terminal = open('/dev/tty')
        except OSError:
            pass
    try:
        status = subprocess.call([sys.executable, str(app), *sys.argv[1:]], stdin=terminal)
    except KeyboardInterrupt:
        status = 130
    finally:
        if terminal is not None:
            terminal.close()
raise SystemExit(status)
'''.replace('PAYLOAD', repr(base64.b64encode(app.read_bytes()).decode()))
launcher.write_text('#!/bin/sh\nset -eu\n'
                    'if ! command -v python3 >/dev/null 2>&1; then\n'
                    '  printf "%s\\n" "需要 Python 3.10 或更新版本；程序不会自动安装依赖。" >&2\n'
                    '  exit 2\nfi\n'
                    'exec python3 -c ' + shlex.quote(bootstrap) + ' "$@"\n')
launcher.chmod(0o755)
bundle = dist / 'Claude-Route-Watch-terminal.zip'
with zipfile.ZipFile(bundle, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
    archive.write(app, app.name)
    archive.write(launcher, launcher.name)
    for name in ('run.sh', 'README.md', 'LICENSE'):
        archive.write(root / name, name)
    archive.write(root / 'docs/ip-reputation.md', 'docs/ip-reputation.md')
checksums = ''.join(hashlib.sha256(path.read_bytes()).hexdigest() + '  ' + path.name + '\n'
                    for path in (app, launcher, bundle))
(dist / 'SHA256SUMS').write_text(checksums)
print(bundle)
print(app)
print(launcher)
