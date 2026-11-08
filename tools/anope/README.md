# Testing with Anope

These files run a real [Anope](https://www.anope.org/) against YamIRCd, using
Anope's own `ngircd` protocol module. They need Docker and Python 3.12 or later.
Run the commands from the repository root.

1. Build Anope 2.1.27 from its source release (a few minutes, once):

   ```sh
   docker build -t yamircd-test-anope:2.1.27 tools/anope
   ```

2. Write an Anope configuration into `anope-conf/` (git ignores it):

   ```sh
   python -I tools/anope/prepare.py anope-conf
   ```

3. Start YamIRCd with a services row, a sasl row and a link listener. With a
   file `services-test.conf` containing

   ```text
   services services.yamircd.test 127.0.0.1 ANOPE_SECRET
   sasl 127.0.0.1:8080 /jsonrpc ANOPE_RPC_TOKEN
   ```

   ```powershell
   $env:ANOPE_SECRET = 'services-secret'
   $env:ANOPE_RPC_TOKEN = 'rpc-secret'
   .\target\release\yamircd.exe --name irc.yamircd.test --listen 127.0.0.1:6667 --link-listen 127.0.0.1:7000 --config services-test.conf
   ```

   On Docker Desktop, a container reaching `host.docker.internal` arrives at the
   host's loopback address, so `127.0.0.1` works for both the listener and the
   services row. On Linux, listen on the Docker bridge address instead, pass
   `--uplink` that address to `prepare.py`, and put the container's address in
   the services row.

4. Start Anope (it keeps no database between runs). Port 8080 is its JSON-RPC
   interface, which YamIRCd uses to check SASL logins:

   ```sh
   docker run --rm --name yamircd-anope -p 127.0.0.1:8080:8080 -v "$PWD/anope-conf:/anope/conf" yamircd-test-anope:2.1.27 --nodb --config=services.conf
   ```

5. Run the checks (registration, IDENTIFY/LOGOUT, `+R`, accounts in WHOIS,
   ChanServ and `+r`, RECOVER, HostServ vhosts, SASL PLAIN):

   ```sh
   python -I tools/anope/e2e.py 127.0.0.1 6667
   ```

   It prints the IRC traffic and a PASS/FAIL line per check, and exits non-zero
   on failure. Restart Anope before running it again, since it registers the
   nickname `alice`. To test a user on another server, link a second YamIRCd to
   the first and point `e2e.py` at the second server's client port.
