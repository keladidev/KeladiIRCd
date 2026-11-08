# Running irctest

[irctest](https://github.com/progval/irctest) is the conformance suite IRC
servers run in CI. `yamircd_controller.py` lets it start YamIRCd, one process
per test.

```sh
git clone --depth 1 https://github.com/progval/irctest.git ../irctest
python -m venv ../irctest-venv
../irctest-venv/bin/pip install -r ../irctest/requirements.txt pytest-xdist
cargo build --release
```

Then, from the irctest checkout (on Windows, use `Scripts\python.exe` and a
`yamircd.exe` path):

```sh
YAMIRCD_BIN=/path/to/YamIRCd/target/release/yamircd \
PYTHONPATH=/path/to/YamIRCd/tools/irctest \
../irctest-venv/bin/python -m pytest --controller yamircd_controller \
  -m "not services and not implementation-specific and not deprecated" \
  -n 6 -q --junitxml=results.xml irctest/server_tests/
```

The marker filter is the one irctest's Makefile uses for servers other than
Ergo. `python -I summarize.py results.xml` groups the results by test file and
lists every failure. The controller listens on `127.0.0.1` (irctest's default
`0.0.0.0` cannot be connected to on Windows) and stops YamIRCd without process
groups, which Windows lacks.
