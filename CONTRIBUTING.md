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
