# KeladiIRCd

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

Settings can also live in a TOML file, passed with `--config keladiircd.toml`;
see [Configuration](#configuration).

Set `KELADIIRCD_PASSWORD` to require a connection password via `PASS`. The password
is read from the environment rather than a command-line argument. This is plain
TCP: for TLS, put a proxy such as stunnel in front, as [docs/TLS.md](docs/TLS.md)
describes; `--proxy-listen` accepts its connections with the users' real
addresses. Accounts and SASL come from linked services (Anope).

On this workspace's local toolchain, PowerShell can run:

```powershell
$env:RUSTUP_HOME = Join-Path $PWD '.tools/rustup'
$env:CARGO_HOME = Join-Path $PWD '.tools/cargo'
& ./.tools/cargo/bin/cargo.exe run --release
```

To run a whole network in Docker (three linked servers, alpha, beta and cypher,
plus Anope), see [docker/README.md](docker/README.md).

## Supported behavior

- `NICK`, `USER`, `PASS`, `CAP LS/LIST/REQ/END`, `PING`, `PONG`, `QUIT`.
- Registration replies `001`–`005`, `LUSERS`, and `MOTD`; CAP negotiation delays
  registration until `CAP END`. The IRCv3 capabilities `multi-prefix` and
  `userhost-in-names` are offered, and `sasl` (PLAIN) when a `[sasl]` section is
  configured (see Linking IRC services).
- `JOIN` (including keys, multiple channels and `JOIN 0`), `PART`, `TOPIC`,
  `NAMES`, `LIST`, `INVITE`, and `KICK`.
- UnrealIRCd's user and channel modes, extended bans and `KNOCK`; see
  [User and channel modes](#user-and-channel-modes).
  Several changes are echoed as one MODE line; invalid keys, limits or
  parameters get `696`.
- New channels start with `+nt`; the first member receives `@` operator status
  (owner `~` comes from services or an override operator). Operator status is
  not automatically reassigned when the last operator leaves. An invitation lets
  a user past `+i`, `+b` and `+l`, but not a key; halfops and above may invite to
  a `+i` channel.
- `PRIVMSG` and `NOTICE` to nicknames or channels, including comma-separated
  targets. NOTICE never produces automatic error replies. Messages are not
  echoed to the sender unless the sender is the direct target.
- `WHO` with a channel, nickname, `*`/`?` wildcard mask, `*`, or `0`; wildcard
  searches skip `+i` users who share no channel with you. `WHOIS` (including
  channels), `WHOWAS` (the last 1024 quits and nickname changes), `USERHOST`,
  `ISON`, `AWAY`, `VERSION`, `INFO`, and `TIME`.
- IPv6 hosts beginning with `:` are shown with a leading `0` (`0::1`) so replies parse.
- Authenticated server links, state bursts, remote messaging and queries,
  deterministic nickname collision handling, auto-reconnect, and netsplit cleanup.
- `OPER`, user mode `+o` (set only by successful OPER), `MODE nick -o`, `KILL`,
  `WALLOPS`, `LINKS`, `SQUIT`, `CONNECT`, `SAJOIN`, `SAPART`, and `SAMODE`.
  `SAJOIN` bypasses keys, bans, limits and invite-only.
- RFC1459 case folding for names, CRLF output, LF-tolerant input, 512-byte wire
  limits, and UTF-8-safe output truncation. NAMES lists split across replies.
  Client-provided prefixes are ignored and replaced with session identity.

## User and channel modes

KeladiIRCd follows [UnrealIRCd 6's modes](https://www.unrealircd.org/docs/User_modes).
`004` and `005` (`CHANMODES`, `PREFIX`, `EXCEPTS`, `INVEX`, `EXTBAN`, `KNOCK`,
`BOT`) advertise them.

**User modes.** A user sets these on itself with `MODE nick +modes`:

| Mode | Meaning |
| --- | --- |
| `B` | Bot: WHOIS shows `335`, WHO shows `B` |
| `d` | Deaf: receives no channel messages |
| `D` | Receives no private messages, except from operators and services |
| `G` | Bad words in messages to you become `<censored>` (`badwords` setting) |
| `i` | Invisible to wildcard WHO from users who share no channel |
| `p` | Hides your channels in WHOIS (from users other than operators) |
| `R` | Private messages only from users logged in to services |
| `T` | Receives no CTCPs (except ACTION) |
| `w` | Receives WALLOPS; OPER sets it |
| `x` | Cloaked host: keyed hashes of the address, such as `1A2B3C4D.5E6F7A8B.9C0D1E2F.IP` (`cloak_key_env` setting) |
| `Z` | Talks privately only with TLS users; needs `z` |

Operators may also set `H` (hide operator status), `I` (hide idle time), `q`
(only services may kick you), `W` (notice when someone WHOISes you), and `s`
with a server notice mask: `MODE nick +s +cFk`, or `+s` alone for `cFGkosv`.
Mask letters: `c` local connects and exits, `F` remote ones, `G` K/G-lines, `k`
kills, `n`/`N` local/remote nick changes, `o` OPER logins, `v` vhosts. Dropping
`+o` drops these too. The server sets `o` (OPER), `r` (identified to services),
`S` (service bots), `t` (a services vhost; `-t` gives it up) and `z` (connected
through the TLS proxy listener). `modes_on_connect` gives every user modes on
connecting, as UnrealIRCd's `modes-on-connect` does.

**Member status**, highest first: `+q` owner `~`, `+a` admin `&`, `+o` operator
`@`, `+h` halfop `%`, `+v` voice `+`. Only owners give `+q`/`+a`; operators give
`+o`/`+h`; halfops give `+v`. No one removes a status higher than their own
(anyone may drop their own), kicks someone of higher status, and halfops kick
only voiced and regular users. Halfops may set `TOPIC` under `+t`, lists, and
`cCGiKmMnNStTV`; the other modes need an operator.

**Channel modes:**

| Mode | Meaning |
| --- | --- |
| `b`, `e`, `I` | Bans, ban exceptions and invite exceptions (60 each; list with `MODE #c b`/`e`/`I`). Plain masks or extended bans |
| `c` | No colours |
| `C` | No CTCPs (except ACTION) |
| `D` | Delayed join: joins show only to operators until the user speaks or gets a status. The server sets `d` while `-D` leaves users hidden |
| `f` | Flood protection, see below |
| `F` | Flood profile: `very-strict`, `strict`, `normal`, `relaxed`, `very-relaxed` (used when no `+f` is set) |
| `G` | Bad words become `<censored>` |
| `H lines:time` | History: up to 200 lines kept up to 7 days (time in minutes, or `30m`, `12h`, `1d`), played to users who join |
| `i`, `k`, `l`, `m`, `n`, `s`, `t` | Invite only, key, limit, moderated, no external messages, secret, protected topic |
| `j joins:seconds` | Each user may join at most this often |
| `K` | No KNOCK |
| `L #channel` | When `+l` is full, joiners go to this channel instead |
| `M` | Only voiced or logged-in users may speak |
| `N` | No nick changes (except halfops and above) |
| `O` | Operators only (an operator sets it) |
| `p` | Private: hidden from LIST and WHOIS for non-members |
| `P` | Permanent: kept with no members (an operator sets it) |
| `Q` | No kicks, except by override operators and services |
| `r` | Registered (services only) |
| `R` | Only users logged in to services may join |
| `S` | Strip colours and formatting |
| `T` | No channel NOTICEs (except operators) |
| `V` | No INVITE |
| `z` | Only TLS users may join; the server sets `Z` while every member uses TLS |

Channel operators are exempt from `c`, `C`, `T` and text bans. Banned users
without voice cannot speak or change nickname.

**`+f`** takes `[<count><kind>#<action><minutes>,...]:<seconds>`, for example
`+f [7c#C15,30j#R5,10k#K15,40m#M10,8n#N15,5t#b,3r]:15`. Kinds count per channel:
`c` CTCPs, `j` joins, `k` knocks, `m` messages, `n` nick changes; or per user:
`t` lines, `r` repeated lines. A kind over its count sets its action mode (`c`:
`C`/`m`/`M`, `j`: `i`/`R`, `k`: `K`, `m`: `m`/`M`, `n`: `N`), which the server
removes after the minutes if given; for `t` and `r` the action is a kick (`k`,
the default) or a ban and kick (`b`). The short form `+f 5:10` (or `*5:10` to
ban as well) limits lines per user. Halfops and above are exempt.

**Extended bans** go in `+b`, `+e` and `+I`, by name or letter (`~a:` is stored
as `~account:`):

| Extban | Matches or does |
| --- | --- |
| `~account:name` (`~a`) | Logged-in account (wildcards; `0` means not logged in) |
| `~channel:[prefix]#chan` (`~c`) | Members of a channel, optionally with at least a status (`~channel:@#ops`) |
| `~operclass:class` (`~O`) | Operators of a class (`local`, `global`, `override`) |
| `~realname:mask` (`~r`) | Real name; `_` matches a space |
| `~securitygroup:group` (`~G`) | `known-users`, `unknown-users`, `tls-users`, `tls-and-known-users` |
| `~quiet:mask` (`~q`) | May join but not speak |
| `~nickchange:mask` (`~n`) | May not change nickname |
| `~join:mask` (`~j`) | May not join, may speak |
| `~forward:#chan:mask` (`~f`) | Banned joiners go to `#chan` instead |
| `~partmsg:mask` (`~p`) | Part messages are hidden |
| `~time:minutes:ban` (`~t`) | Removed after the minutes |
| `~text:block:pattern` / `~text:censor:word` (`~T`) | Blocks matching messages, or censors a word |
| `~msgbypass:what:mask` (`~m`, `+e` only) | Lets matching users past `external`, `moderated`, `censor`, `color`, `notice` or `ctcp` |

`~quiet`, `~nickchange` and `~join` take a mask or one of the first five
extbans; in `+e` they except only that restriction.

`KNOCK #channel [:reason]` asks the operators of an invite-only channel for an
invitation (`480` when the channel is not `+i`, is `+K`, or bans you).

## Limits and scope

256 connections per server by default (`--max-users N` sets 1-100000; at most
10 of them unregistered from one IP address), 33 times the larger of that and
256 users network-wide (when raising `--max-users`, raise it on every linked
server, or a link drops when the network outgrows the smaller servers' limit), 8 direct links, 32 remote servers,
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
implementation. Built-in services, SASL without Anope, SASL mechanisms other
than PLAIN, native TLS (see [docs/TLS.md](docs/TLS.md)), the extended bans
`~certfp`, `~country`, `~asn` and `~inherit`, CHATHISTORY and `server-time` (+H
replays plain lines), WHOX, MONITOR, and other administrative commands are not
implemented. Halfop, admin and owner prefixes use `&`, which is also the local
channel type, so a client may misread an admin's local channel in WHOIS.
Unknown commands or modes receive the corresponding numeric errors. Message tags
are not negotiated or relayed.

Each user takes two threads and one shared state lock. Measured on Windows with
the test clients on the same machine (`tools/load`): 4000 idle users took about
450 MB and 8000 threads, with channel messages still delivered in 0.1-0.2 ms;
250 users all in one channel at 100 messages a second (25,000 deliveries a
second) used 17% of one core with 1.3 ms median delay. Larger counts are untested.

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
KeladiIRCd, and [`tools/anope`](tools/anope) runs a real Anope in Docker with an
end-to-end check of NickServ and ChanServ. [`tools/load`](tools/load) is a load
test: on a Windows desktop, 250 clients in one channel at 100 messages a second
(about 25,000 deliveries a second) see 1.3 ms median and 2.5 ms 99th-percentile
delivery delay at about 17% of one CPU core, and with 5000 channel memberships a
PING round trip takes 1.2 ms.

## Linking two servers

The [link protocol](docs/LINK_PROTOCOL.md) is KeladiIRCd-specific, inspired by
[UnrealIRCd's link configuration](https://www.unrealircd.org/docs/Link_block).
It does **not** link directly to UnrealIRCd. Run one outgoing connection per edge
of your network tree. Both peers need a `[[link]]` block for each other and the
same secret.

In each PowerShell terminal, set the secrets (replace these examples):

```powershell
$env:KELADIIRCD_NET_SECRET = 'replace-with-a-long-shared-secret'
$env:KELADIIRCD_ADMIN_SECRET = 'replace-with-a-different-operator-secret'
```

Run server A:

```powershell
.\target\release\keladiircd.exe --config examples/a.toml
```

Run server B in another terminal:

```powershell
.\target\release\keladiircd.exe --config examples/b.toml
```

Clients on either server can join the same `#general` and chat. `&local` channels
stay on their own server. Links and operator logins use plain TCP; use an encrypted
tunnel when crossing an untrusted network ([docs/TLS.md](docs/TLS.md) shows
stunnel for links). Link handshakes prove the shared secret
with HMAC-SHA256 challenge-response, so the secret itself is never sent, but the
traffic that follows is readable. Link peers are fully trusted.

[`examples/a.toml`](examples/a.toml) and [`examples/b.toml`](examples/b.toml)
hold each server's name, listeners, link and operator; see
[Configuration](#configuration) for every key.

## Configuration

`--config FILE` reads a [TOML](https://toml.io) file.
[`examples/keladiircd.toml`](examples/keladiircd.toml) explains every key with its
default value and ends with short examples: a single server, two linked servers,
Anope services, a TLS proxy and operators. In short:

```toml
name = "a.local"                 # also: description, listen, link_listen,
link_listen = "127.0.0.1:7001"   #       proxy_listen, max_users

[[link]]                         # one block per linked server
name = "b.local"
connect = "127.0.0.1:7002"       # leave out to only accept the link
incoming_ip = "127.0.0.1"
password_env = "KELADIIRCD_NET_SECRET"

[[oper]]                         # one block per /OPER login
name = "admin"
ip_mask = "127.0.0.1"            # * and ? wildcards over the client IP
class = "override"               # local, global or override
password_env = "KELADIIRCD_ADMIN_SECRET"

[[services]]                     # Anope, see Linking IRC services
name = "services.local"
incoming_ip = "127.0.0.1"
password_env = "KELADIIRCD_SERVICES_SECRET"

[sasl]                           # SASL PLAIN checked by Anope
address = "127.0.0.1:8080"
path = "/jsonrpc"                # the default
token_env = "KELADIIRCD_ANOPE_RPC_TOKEN"
```

`incoming_ip` is an exact IP address. `connect` is a numeric `IP:port` address
(bracket IPv6 addresses). Keys ending in `_env` name environment variables, not
literal passwords. Missing variables, unknown keys and invalid values stop startup
with an error naming the line. Operator names and passwords are case sensitive.
Command-line flags override the file. Configuration is read at startup.

### Upgrading from the line-based config

Earlier versions read one row per entry. KeladiIRCd now refuses those files with
an error pointing here. Rewrite each row as a block (and, if you like, move
`--name`, `--listen` and the other flags into the file):

| Old row | New block |
| --- | --- |
| `link NAME ADDRESS INCOMING_IP ENV` | `[[link]]` with `name`, `connect = "ADDRESS"`, `incoming_ip`, `password_env = "ENV"` |
| `link NAME - INCOMING_IP ENV` | the same without `connect` |
| `oper NAME IP_MASK CLASS ENV` | `[[oper]]` with `name`, `ip_mask`, `class`, `password_env` |
| `services NAME INCOMING_IP ENV` | `[[services]]` with `name`, `incoming_ip`, `password_env` |
| `sasl ADDRESS PATH ENV` | `[sasl]` with `address`, `path`, `token_env` |

Every value is quoted. For example, `link b.local - 127.0.0.1 NET_SECRET` becomes

```toml
[[link]]
name = "b.local"
incoming_ip = "127.0.0.1"
password_env = "NET_SECRET"
```

## Linking IRC services (Anope)

Services such as [Anope](https://www.anope.org/) link to the `--link-listen` port
using the ngIRCd server protocol (RFC 2813 plus ngIRCd's extensions), which Anope
supports with its `ngircd` protocol module. Add a `[[services]]` block naming the
services server, the IP it connects from, and the secret variable:

```toml
[[services]]
name = "services.example.net"
incoming_ip = "127.0.0.1"
password_env = "KELADIIRCD_SERVICES_SECRET"
```

In Anope's `services.conf`, set `serverinfo` `name` to the same server name, point
`uplink` at the link listener with the same password, load `module { name = "ngircd" }`,
and set `networkinfo` `nicklen = 30`. Services may link to any server of a KeladiIRCd
network; users on every server see the service bots and can use them.

Anope's ngIRCd module has no SASL, so KeladiIRCd checks SASL PLAIN logins itself
through Anope's JSON-RPC interface (`anope.checkCredentials`), then tells
services the user's account as usual. In Anope's `modules.conf`, load `httpd`
(keep it on loopback or a private network), `jsonrpc` with a token allowed the
`anope.checkCredentials` method, and `rpc_user`; then add a `[sasl]` section with
Anope's httpd address and a variable holding the same token (`path` defaults to
`/jsonrpc`):

```toml
[sasl]
address = "127.0.0.1:8080"
token_env = "KELADIIRCD_ANOPE_RPC_TOKEN"
```

Tested with Anope 2.1.27 (`tools/anope`): nickname registration, IDENTIFY and
LOGOUT, `+r` (ngIRCd's `+R`) and the account shown in WHOIS (`330`, `307`, `900`/`901`), SASL
PLAIN, ChanServ channel registration (`+r`) and modes, HostServ vhosts (`396`;
operators and the user themself see the real host in WHOIS `378`), NickServ
RECOVER (KILL and SVSNICK), service bots in channels, kicks and mode changes
reported from the user who made them, and OperServ AKILL (sent as GLINE;
OperServ requires IRC operator status). Service bots act with operator-override
privileges.

Not supported: SVSJOIN and SVSPART, so NickServ AJOIN and OperServ SVSJOIN do not
work. Anope's ngIRCd module never sends them (it does not mark the protocol as
able to), so no change in KeladiIRCd can enable them.

## IRC operator privileges

Following [UnrealIRCd's operator model](https://www.unrealircd.org/docs/Oper_block),
`OPER` credentials and the user's source IP determine their operator class.

| Class | Privileges |
| --- | --- |
| `local` | KILL local users, send WALLOPS (to users with `+w`) |
| `global` | Also KILL remote users, SQUIT direct links, enable configured links with CONNECT, set KLINE and GLINE |
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
/GLINE *@192.0.2.* 3600 :Abuse from this range
/KLINE baduser@* 0 :Not on this server
/STATS g
/GLINE *@192.0.2.*
/MODE your-nickname -o
```

Successful OPER sends numeric `381` and MODE `+ow`; WHOIS shows numeric `313`.
`KLINE` bans users from one server and `GLINE` from the whole network:
`<mask> <seconds> :<reason>` adds a ban (0 seconds is permanent) and `<mask>`
alone removes it. Masks are `user@host`, `nick!user@host` or a host; matching
ignores the `~` before usernames, and masks matching everyone are refused.
Matching users are disconnected with `465`, and `STATS k` / `STATS g` list bans.
Users cannot give themselves `+o` with MODE. A global operator can `/CONNECT
server-name` to re-enable a link disabled by SQUIT: an outgoing link is dialled
again, and an incoming-only link is accepted again when the peer reconnects. In
the example, B initiates the connection, so A's operator re-enables it with
`/CONNECT b.local` and B's own retry brings it back. Local credentials are never
sent over links.
