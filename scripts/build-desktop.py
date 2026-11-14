"""Build a self-contained macOS app. Run in the isolated desktop build environment."""
import importlib.metadata
from pathlib import Path
import platform
import plistlib
import subprocess
import sys

root = Path(__file__).resolve().parent.parent
if sys.platform != 'darwin':
    raise SystemExit('The desktop bundle currently targets macOS only.')
subprocess.run([
    sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean', '--windowed', '--onedir',
    '--name', 'Claude Route Watch', '--osx-bundle-identifier', 'io.github.majiayu000.claude-route-watch',
    '--add-data', str(root / 'docs/app.html') + ':docs', '--collect-data', 'webview',
    '--hidden-import', 'webview.platforms.cocoa', '--distpath', str(root / 'dist'),
    '--workpath', str(root / 'build/desktop'), '--specpath', str(root / 'build'), str(root / 'desktop.py'),
], check=True, cwd=root)
app = root / 'dist/Claude Route Watch.app'
info = app / 'Contents/Info.plist'
with info.open('rb') as stream:
    data = plistlib.load(stream)
data['CFBundleShortVersionString'] = importlib.metadata.version('claude-route-watch')
data['CFBundleVersion'] = data['CFBundleShortVersionString']
data['NSHighResolutionCapable'] = True
with info.open('wb') as stream:
    plistlib.dump(data, stream)
# An ad-hoc signature permits local execution; it is NOT Developer ID or notarization.
subprocess.run(['codesign', '--force', '--deep', '--sign', '-', str(app)], check=True)
archive = root / ('dist/Claude-Route-Watch-macOS-' + platform.machine() + '.zip')
subprocess.run(['ditto', '-c', '-k', '--sequesterRsrc', '--keepParent', str(app), str(archive)], check=True)
print(archive)
