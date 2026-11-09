# Running irctest

[irctest](https://github.com/progval/irctest) is the conformance suite IRC
servers run in CI. `keladiircd_controller.py` lets it start KeladiIRCd, one process
per test.

```sh
git clone --depth 1 https://github.com/progval/irctest.git ../irctest
python -m venv ../irctest-venv
../irctest-venv/bin/pip install -r ../irctest/requirements.txt pytest-xdist
cargo build --release
```

Then, from the irctest checkout (on Windows, use `Scripts\python.exe` and a
`keladiircd.exe` path):

```sh
KELADIIRCD_BIN=/path/to/KeladiIRCd/target/release/keladiircd \
PYTHONPATH=/path/to/KeladiIRCd/tools/irctest \
../irctest-venv/bin/python -m pytest --controller keladiircd_controller \
  -m "not services and not implementation-specific and not deprecated" \
  -n 6 -q --junitxml=results.xml irctest/server_tests/
```

The marker filter is the one irctest's Makefile uses for servers other than
Ergo. `python -I summarize.py results.xml` groups the results by test file and
lists every failure. The controller listens on `127.0.0.1` (irctest's default
`0.0.0.0` cannot be connected to on Windows) and stops KeladiIRCd without process
groups, which Windows lacks.
