# YamIRCd

A dependency-free Rust IRC daemon for a small linked network. Implements a
practical subset of the [Modern IRC Client Protocol](https://modern.ircdocs.horse/).

## Run

Install stable Rust, then:

```sh
cargo run --release -- --listen 127.0.0.1:6667 --name irc.local
```

Connect an IRC client to `127.0.0.1`, port `6667`, with TLS disabled. Choose a
nickname and join `#general`. The default listener is loopback; use
`--listen 0.0.0.0:6667` to accept remote clients.

Set `YAMIRCD_PASSWORD` to require a connection password via `PASS`. The password
is read from the environment rather than a command-line argument. This is plain
TCP: use a TLS terminator for encrypted connections. No accounts or SASL are
implemented.

On this workspace's local toolchain, PowerShell can run:

```powershell
$env:RUSTUP_HOME = Join-Path $PWD '.tools/rustup'
$env:CARGO_HOME = Join-Path $PWD '.tools/cargo'
& ./.tools/cargo/bin/cargo.exe run --release
```

## Supported behavior

- `NICK`, `USER`, `PASS`, `CAP LS/LIST/REQ/END`, `PING`, `PONG`, `QUIT`.
- Registration replies `001`–`005`, `LUSERS`, and `MOTD`; CAP negotiation delays
  registration until `CAP END`. The IRCv3 capabilities `multi-prefix` and
  `userhost-in-names` are offered.
- `JOIN` (including keys, multiple channels and `JOIN 0`), `PART`, `TOPIC`,
  `NAMES`, `LIST`, `INVITE`, and `KICK`.
- Channel modes: `+b` bans (up to 60 masks, listed with `MODE #channel b`), `+k`
  key, `+l` limit, `+i` invite-only, `+m` moderated, `+n` no external messages,
  `+s` secret, `+t` protected topic, and member status `+o`/`+v` (`@`/`+`).
  Several changes are echoed as one MODE line; invalid keys or limits get `696`.
- New channels start with `+nt`; the first member receives `@` operator status.
  Channel operators may change modes and protected topics, or kick. Operator
  status is not automatically reassigned when the last operator leaves. An
  invitation lets a user past `+i`, `+b` and `+l`, but not a key; only channel
  operators may invite to a `+i` channel.
- `PRIVMSG` and `NOTICE` to nicknames or channels, including comma-separated
  targets. NOTICE never produces automatic error replies. Messages are not
  echoed to the sender unless the sender is the direct target.
- `WHO` with a channel, nickname, `*`/`?` wildcard mask, `*`, or `0`; wildcard
  searches skip `+i` users who share no channel with you. `WHOIS` (including
  channels), `WHOWAS` (the last 1024 quits and nickname changes), `USERHOST`,
  `ISON`, `AWAY`, `VERSION`, `INFO`, and `TIME`.
- User mode `+i` (invisible); `+w` is accepted without effect because WALLOPS
  always reach every operator.
- IPv6 hosts beginning with `:` are shown with a leading `0` (`0::1`) so replies parse.
- Authenticated server links, state bursts, remote messaging and queries,
  deterministic nickname collision handling, auto-reconnect, and netsplit cleanup.
- `OPER`, user mode `+o` (set only by successful OPER), `MODE nick -o`, `KILL`,
  `WALLOPS`, `LINKS`, `SQUIT`, `CONNECT`, `SAJOIN`, `SAPART`, and `SAMODE`.
  `SAJOIN` bypasses keys, bans, limits and invite-only.
- RFC1459 case folding for names, CRLF output, LF-tolerant input, 512-byte wire
  limits, and UTF-8-safe output truncation. NAMES lists split across replies.
  Client-provided prefixes are ignored and replaced with session identity.

## Limits and scope

256 connections per server (at most 10 of them unregistered from one IP address),
8448 users network-wide, 8 direct links, 32 remote servers,
20 channels per client, 30-byte ASCII nicknames, 50-byte channel
names, 12-byte usernames, 300-byte topics. Each client has a bounded output queue;
slow clients disconnect. A client sending more than 100 lines in a one-second
window disconnects. Registration expires after 60 seconds. Idle registered
clients receive a PING after 120 seconds and have 60 seconds to answer its token.
Three wrong connection passwords (`464`) or failed OPER attempts close the
connection; repeating the same wrong password does not count again.
The server advertises `UTF8ONLY`: a non-UTF-8 line receives `FAIL <command> INVALID_UTF8`
and is discarded. Oversized lines receive `417` and are discarded.

State is in memory and disappears on restart. This is not a complete UnrealIRCd
implementation. Built-in services, SASL, native TLS, other user modes, ban
exceptions (`+e`), invite exceptions (`+I`), extended bans, WHOX, MONITOR,
server bans (KLINE/GLINE), and other administrative commands are not implemented.
Unknown commands or modes receive the corresponding numeric errors. Message tags
are not negotiated or relayed. The thread-per-client design targets small networks.

[irctest](https://github.com/progval/irctest), run with the filter other servers
use (`-m "not services and not implementation-specific and not deprecated"`),
passes every test that applies; the rest skip because they need optional
extensions listed above.

## Verify

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

The tests launch daemons on ephemeral loopback ports and exercise real TCP client
registration, CAP negotiation, password checks, channel permissions, messaging,
queries, nickname changes, QUIT cleanup, framing, and malformed input. Network
tests use two- and three-server topologies to cover state bursts, remote actions,
operator privilege boundaries, link authentication, collisions, and netsplits.
A fake services server checks the services link handshake, burst, logins,
forced nickname changes, kills, and that services' own changes are not echoed.

[`tools/irctest`](tools/irctest) runs the irctest conformance suite against
YamIRCd, and [`tools/anope`](tools/anope) runs a real Anope in Docker with an
end-to-end check of NickServ and ChanServ.

## Linking two servers

The [link protocol](docs/LINK_PROTOCOL.md) is YamIRCd-specific, inspired by
[UnrealIRCd's link configuration](https://www.unrealircd.org/docs/Link_block).
It does **not** link directly to UnrealIRCd. Run one outgoing connection per edge
of your network tree. Both peers need a configuration row and the same secret.

In each PowerShell terminal, set the secrets (replace these examples):

```powershell
$env:YAMIRCD_NET_SECRET = 'replace-with-a-long-shared-secret'
$env:YAMIRCD_ADMIN_SECRET = 'replace-with-a-different-operator-secret'
```

Run server A:

```powershell
.\target\release\yamircd.exe --name a.local --listen 127.0.0.1:6667 --link-listen 127.0.0.1:7001 --config examples/a.conf
```

Run server B in another terminal:

```powershell
.\target\release\yamircd.exe --name b.local --listen 127.0.0.1:6668 --link-listen 127.0.0.1:7002 --config examples/b.conf
```

Clients on either server can join the same `#general` and chat. `&local` channels
stay on their own server. Links and operator logins use plain TCP; use an encrypted
tunnel when crossing an untrusted network. Link handshakes prove the shared secret
with HMAC-SHA256 challenge-response, so the secret itself is never sent, but the
traffic that follows is readable. Link peers are fully trusted.

Configuration files contain one row per account or peer:

```text
oper NAME IP_MASK CLASS PASSWORD_ENV
link SERVER OUTGOING_ADDRESS_OR_- INCOMING_IP PASSWORD_ENV
services SERVER INCOMING_IP PASSWORD_ENV
```

`IP_MASK` accepts `*` and `?` over textual client IPs. `INCOMING_IP` is an exact
IP address. Outgoing addresses are numeric `IP:port` socket addresses (bracket
IPv6 addresses). `-` means incoming only. Secret fields name environment variables,
not literal passwords. Missing variables or invalid rows stop startup. Operator
names and passwords are case sensitive. Configuration is read at startup.

## Linking IRC services (Anope)

Services such as [Anope](https://www.anope.org/) link to the `--link-listen` port
using the ngIRCd server protocol (RFC 2813 plus ngIRCd's extensions), which Anope
supports with its `ngircd` protocol module. Add a `services` row naming the
services server, the IP it connects from, and the secret variable:

```text
services services.example.net 127.0.0.1 YAMIRCD_SERVICES_SECRET
```

In Anope's `services.conf`, set `serverinfo` `name` to the same server name, point
`uplink` at the link listener with the same password, load `module { name = "ngircd" }`,
and set `networkinfo` `nicklen = 30`. Services may link to any server of a YamIRCd
network; users on every server see the service bots and can use them.

Tested with Anope 2.1.27: nickname registration, IDENTIFY and LOGOUT, `+R` and the
account shown in WHOIS (`330`, `307`, `900`/`901`), ChanServ channel registration
and modes, NickServ RECOVER (KILL and SVSNICK), and service bots in channels.
Service bots act with operator-override privileges. Not supported: SASL and
SVSJOIN (Anope's ngIRCd module lacks them, so `ns_sasl*` and `ns_ajoin` do not
load), virtual hosts (HostServ), AKILL/GLINE, and the registered channel mode `+r`.
Services learn about kicks of ordinary users as PART, and about mode changes as
coming from the user's server.

## IRC operator privileges

Following [UnrealIRCd's operator model](https://www.unrealircd.org/docs/Oper_block),
`OPER` credentials and the user's source IP determine their operator class.

| Class | Privileges |
| --- | --- |
| `local` | KILL local users, send WALLOPS to network operators |
| `global` | Also KILL remote users, SQUIT direct links, enable configured links with CONNECT |
| `override` | Also bypass channel MODE/TOPIC/KICK permission checks and use SAJOIN, SAPART, SAMODE |

Example client commands on server A:

```text
/OPER admin replace-with-a-different-operator-secret
/WHOIS admin-nickname
/WALLOPS Maintenance starts soon
/KILL troublesome-nickname Repeated flooding
/SAJOIN nickname #help
/SAPART nickname #general
/SAMODE #general +o nickname
/LINKS
/SQUIT b.local Maintenance
/MODE your-nickname -o
```

Successful OPER sends numeric `381` and MODE `+o`; WHOIS shows numeric `313`.
Users cannot give themselves `+o` with MODE. A global operator can `/CONNECT
server-name` to re-enable a link disabled by SQUIT: an outgoing link is dialled
again, and an incoming-only link is accepted again when the peer reconnects. In
the example, B initiates the connection, so A's operator re-enables it with
`/CONNECT b.local` and B's own retry brings it back. Local credentials are never
sent over links.
