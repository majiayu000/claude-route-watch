#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if ! command -v python3 >/dev/null 2>&1 || ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))'; then
    printf '%s\n' '需要 Python 3.10 或更新版本。请用系统包管理器安装后重试；此脚本不会自动修改系统。' >&2
    exit 2
fi
if [ -f "$root/claude-route-watch.pyz" ]; then
    exec python3 "$root/claude-route-watch.pyz" "$@"
fi
if [ -f "$root/claude_route_watch.py" ]; then
    exec python3 "$root/claude_route_watch.py" "$@"
fi
printf '%s\n' '请解压完整终端包后运行 run.sh；不能只下载这个启动脚本。' >&2
exit 2
