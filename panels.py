"""Fixed-region terminal dashboard: verdict bar, exit | route boxes, sources, steps, keys.

Pure layout. A view is a dict built by views.py; nothing here queries the network.
Wide terminals (>= 80 usable columns) put the exit and route boxes side by side;
narrower ones stack every box so the reading order stays the same.
"""
import os
import shutil
import sys
import threading
import time
import unicodedata

WIDE = 80
STYLE = {'h': '1;36', 'acc': '36', 'ok': '32', 'okb': '1;32', 'warn': '33', 'warnb': '1;33',
         'bad': '31', 'badb': '1;31', 'dim': '90', 'b': '1', 'key': '7', 'line': '90', 'rule': '36',
         'vok': '1;30;42', 'vwarn': '1;30;43', 'vbad': '1;97;41'}
SPIN = '⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'


def color_enabled():
    return sys.stdout.isatty() and 'NO_COLOR' not in os.environ and os.environ.get('TERM') != 'dumb'


def clean(value):
    """Remote names must not emit terminal control sequences."""
    return ''.join(char if char.isprintable() else ' ' for char in str(value))


def cw(text):
    return sum(0 if unicodedata.combining(c) else 2 if unicodedata.east_asian_width(c) in 'WF' else 1
               for c in text)


def seg(text, style=''):
    return (clean(text), style)


def width(line):
    return sum(cw(text) for text, _ in line)


def fit(line, limit):
    """Clip a styled line to limit cells, marking the cut with an ellipsis."""
    out, used = [], 0
    for text, style in line:
        if used + cw(text) <= limit:
            out.append((text, style))
            used += cw(text)
            continue
        cut = ''
        for char in text:
            if used + cw(cut + char) > limit - 1:
                break
            cut += char
        out.append((cut + '…', style))
        break
    return out


def pad(line, size):
    return line + [(' ' * max(0, size - width(line)), '')]


def col(text, size, style=''):
    text = clean(text)
    return (text + ' ' * max(0, size - cw(text)), style)


def kv(key, value, style=''):
    parts = value if isinstance(value, list) else [seg(value, style)]
    return [col(key, 6, 'dim')] + parts


def box(title, rows, size, alert=False):
    tone = 'bad' if alert else 'line'
    inner = size - 4
    head = [('╭─ ', tone), (title, 'badb' if alert else 'h'), (' ' + '─' * max(0, size - 5 - cw(title)) + '╮', tone)]
    body = [[('│ ', tone)] + pad(fit(row, inner), inner) + [(' │', tone)] for row in rows]
    return [head] + body + [[('╰' + '─' * (size - 2) + '╯', tone)]]


def side_by_side(left, right, gap=2):
    left_width = max(width(row) for row in left)
    rows = max(len(left), len(right))
    left += [[]] * (rows - len(left))
    right += [[]] * (rows - len(right))
    return [pad(a, left_width) + [(' ' * gap, '')] + b for a, b in zip(left, right)]


def keys_line(keys):
    line = []
    for key, label in keys:
        line += [(' ' + key + ' ', 'key'), (' ' + label + '  ', 'dim')]
    return line


def layout(view, columns):
    """Return styled lines for a view at the given terminal width."""
    size = WIDE if columns >= WIDE else max(30, columns)
    wide = size == WIDE
    verdict, tone = view['verdict']
    title = [(' ' + verdict + ' ', tone), seg('  ' + view['why'], 'b')]
    if wide:
        title = [('CLAUDE ROUTE WATCH', 'h'), ('  ', '')] + title
    right = view.get('right', '')
    if right and width(title) + cw(right) + 2 <= size:
        title = pad(title, size - cw(right)) + [(right, 'dim')]
    lines = [fit(title, size), [('━' * size, 'rule')]]
    left_box, right_box = view['boxes']
    if wide:
        lines += side_by_side(box(*left_box, 39), box(*right_box, 39))
    else:
        lines += box(*left_box, size) + box(*right_box, size)
    rows = list(view['sources'])
    if wide:
        rows = [[col('来源', 13, 'dim'), col('状态', 10, 'dim'), ('指标 / 说明', 'dim')]] + rows + [[]]
    lines += box('信誉来源', rows + [view['grade']], size, alert=view.get('alert', False))
    if view.get('steps') and (wide or view.get('running')):
        lines.append(fit([('检测  ', 'dim')] + view['steps'], size))
    if view.get('note'):
        lines.append(fit([seg(view['note'], 'dim')], size))
    if view.get('keys'):
        lines.append(fit(keys_line(view['keys']), size))
    return lines


def render(lines, colored):
    out = []
    for line in lines:
        text = ''
        for part, style in line:
            code = STYLE.get(style)
            text += f'\033[{code}m{part}\033[0m' if colored and code and part else part
        out.append(text.rstrip() if not colored else text)
    return out


def columns():
    return shutil.get_terminal_size((WIDE, 24)).columns


def show(view):
    for text in render(layout(view, columns()), color_enabled()):
        print(text)
    sys.stdout.flush()


class Region:
    """Redraw a block of lines in place (TTY only); falls back to plain printing."""

    def __init__(self):
        self.drawn = 0
        self.live = sys.stdout.isatty() and os.environ.get('TERM') != 'dumb'

    def draw(self, view):
        lines = render(layout(view, columns()), color_enabled())
        if self.live and self.drawn:
            sys.stdout.write(f'\033[{self.drawn}F\033[J')
        sys.stdout.write('\n'.join(lines) + '\n')
        sys.stdout.flush()
        self.drawn = len(lines) if self.live else 0

    def clear(self):
        if self.live and self.drawn:
            sys.stdout.write(f'\033[{self.drawn}F\033[J')
            sys.stdout.flush()
        self.drawn = 0


class Live:
    """Spinner-driven progress dashboard. state is updated from real check events only."""

    def __init__(self, build):
        self.build = build  # build(state, spinner, elapsed) -> view
        self.state = {}
        self.region = Region()
        self.lock = threading.Lock()
        self.stopped = threading.Event()
        self.started = time.monotonic()
        self.thread = None

    def event(self, stage, info):
        with self.lock:
            self.state.setdefault('events', []).append((stage, dict(info)))
            if self.thread:
                self._draw()

    def _draw(self):
        frame = int((time.monotonic() - self.started) * 10)
        self.region.draw(self.build(self.state, SPIN[frame % len(SPIN)], time.monotonic() - self.started))

    def _tick(self):
        while not self.stopped.wait(0.1):
            with self.lock:
                self._draw()

    def __enter__(self):
        if not self.region.live:
            return self
        sys.stdout.write('\033[?25l')
        with self.lock:
            self._draw()
        self.thread = threading.Thread(target=self._tick, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.stopped.set()
        if self.thread:
            self.thread.join()
        with self.lock:
            self.region.clear()
        if self.region.live:
            sys.stdout.write('\033[?25h')
            sys.stdout.flush()
        return False
