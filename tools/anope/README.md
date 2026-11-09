# Testing with Anope

These files run a real [Anope](https://www.anope.org/) against KeladiIRCd, using
Anope's own `ngircd` protocol module. They need Docker and Python 3.12 or later.
Run the commands from the repository root.

1. Build Anope 2.1.27 from its source release (a few minutes, once):

   ```sh
   docker build -t keladiircd-test-anope:2.1.27 tools/anope
   ```

2. Write an Anope configuration into `anope-conf/` (git ignores it):

   ```sh
   python -I tools/anope/prepare.py anope-conf
   ```

3. Start KeladiIRCd with a `[[services]]` block, a `[sasl]` section and a link
   listener. With a file `services-test.toml` containing

   ```toml
   [[services]]
   name = "services.keladiircd.test"
   incoming_ip = "127.0.0.1"
   password_env = "ANOPE_SECRET"

   [sasl]
   address = "127.0.0.1:8080"
   token_env = "ANOPE_RPC_TOKEN"
   ```

   ```powershell
   $env:ANOPE_SECRET = 'services-secret'
   $env:ANOPE_RPC_TOKEN = 'rpc-secret'
   .\target\release\keladiircd.exe --name irc.keladiircd.test --listen 127.0.0.1:6667 --link-listen 127.0.0.1:7000 --config services-test.toml
   ```

   On Docker Desktop, a container reaching `host.docker.internal` arrives at the
   host's loopback address, so `127.0.0.1` works for both the listener and the
   `[[services]]` block. On Linux, listen on the Docker bridge address instead, pass
   `--uplink` that address to `prepare.py`, and put the container's address in
   the `[[services]]` block's `incoming_ip`.

4. Start Anope (it keeps no database between runs). Port 8080 is its JSON-RPC
   interface, which KeladiIRCd uses to check SASL logins:

   ```sh
   docker run --rm --name keladiircd-anope -p 127.0.0.1:8080:8080 -v "$PWD/anope-conf:/anope/conf" keladiircd-test-anope:2.1.27 --nodb --config=services.conf
   ```

5. Run the checks (registration, IDENTIFY/LOGOUT, `+r`, accounts in WHOIS,
   ChanServ and `+r`, RECOVER, HostServ vhosts, SASL PLAIN):

   ```sh
   python -I tools/anope/e2e.py 127.0.0.1 6667
   ```

   For the `docker/` network, give Anope's name, and set `SERVICES_ROOT=alice`
   in `docker/.env` so the HostServ check can pass after alice opers up:

   ```sh
   python -I tools/anope/e2e.py 127.0.0.1 6668 --services services.irc.test --oper admin <beta's oper password>
   ```

   It prints the IRC traffic and a PASS/FAIL line per check, and exits non-zero
   on failure. Restart Anope before running it again, since it registers the
   nickname `alice`. To test a user on another server, link a second KeladiIRCd to
   the first and point `e2e.py` at the second server's client port.
