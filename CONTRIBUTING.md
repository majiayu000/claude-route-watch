# Contributing

```sh
git clone https://github.com/majiayu000/claude-route-watch.git
cd claude-route-watch
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/python -m unittest discover -v
.venv/bin/python -m pip wheel --no-deps . --wheel-dir dist
```

Keep changes small. For scoring changes, explain the evidence, show the result before/after, update the scoring version if the meaning changes, and include a synthetic regression snapshot. Do not add claims about ban probabilities without a defensible labeled dataset. Never submit real controller secrets, credentials, local process paths, or unredacted connection captures.

## Build the native macOS app

```sh
.venv/bin/python -m pip install '.[desktop]' pyinstaller==6.22.3
.venv/bin/python scripts/build-desktop.py
```

The self-contained app and architecture-labeled ZIP appear in `dist/`. Build on the intended macOS architecture. No signing identity is used: the script applies an ad-hoc signature, which does not imply notarization or bypass downloaded-app approval. Never bundle local preferences, live reports, or API keys. Desktop model tests run without native GUI dependencies; live native acceptance is a separate check.
