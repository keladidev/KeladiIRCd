# YamIRCd server protocol, version 2

This is a YamIRCd-specific protocol. It does **not** implement UnrealIRCd's
`PROTOCTL`, `UID`, `SJOIN`, or other UnrealIRCd wire formats, and cannot link
directly to UnrealIRCd or Anope. The design follows the distinction between
[authenticated links](https://www.unrealircd.org/docs/Link_block) and
[operator classes](https://www.unrealircd.org/docs/Oper_block).

## Transport and authentication

Services servers such as Anope use the same listener but speak the ngIRCd
protocol instead; a connection whose first line is not `YAMLINK` is treated as
one. See the README's services section.

Links use a dedicated TCP listener. Configure each peer's exact server name,
incoming source IP, shared secret, and optional outgoing socket address. One
side initiates the connection. Outgoing links retry every two seconds; a
successful link replaces the retry loop until it disconnects. Configure a tree,
with unique server names. The handshake compares known server names to reject
duplicate connections and cycles; later SERVER introductions also check duplicates.

The outgoing side sends:

```text
YAMLINK 2 <server-name> <hex-secret> <hex-comma-separated-known-server-names>
```

The incoming side authenticates name, source IP, and secret before returning the
same format with its own identity. Each side verifies the other before accepting
state. Both peers must speak the same version: version 2 added channel modes,
voice, invisible users and invitations, so it does not link with version 1. Hex encoding is framing, **not encryption**. Use private loopback links
or an authenticated encrypted tunnel for remote links. Linked servers are fully
trusted network administrators, including authority to announce operators.

Each frame ends in CRLF and is at most 8192 bytes before CRLF. Variable text
fields use lowercase UTF-8 hex; `-` represents the empty string. NUL, CR, and LF
inside decoded text are invalid. Input lines have a ten-second read deadline;
malformed frames disconnect the peer. Each link has a bounded 16384-frame queue.
Idle links exchange PING/PONG and disconnect after a further unanswered timeout.

## State and delivery

UIDs are `<home-server>!<boot-milliseconds>!<local-counter>`. User introductions
must come through the known route to their home server. A peer cannot introduce
a user owned by the receiver or by another branch of the tree.

| Frame | Fields after command | Purpose |
| --- | --- | --- |
| SERVER | name | Introduce a reachable server |
| USER | uid hex-nick hex-user hex-host hex-realname hex-away oper-class hex-modes hex-account | Introduce/update a user; class is `-`, `local`, `global`, or `override`; modes are letters from `iR` (invisible, identified); the host is an IP or, for service bots, a hostname |
| CHAN | hex-name revision revision-server hex-flags hex-key limit hex-topic hex-setter topic-time created hex-comma-separated-bans | Replicate channel metadata; flags are letters from `imnst`, limit 0 = none |
| MEMBER | hex-channel uid status revision revision-server | Add/update membership; status bits 1 = operator, 2 = voice (0-3), `-` = removal |
| WIRE | recipient-uid hex-client-message | Route one already-authorized client delivery |
| REMOVE | uid hex-reason | Remove a quit/killed user |
| COLLIDE | losing-uid | Resolve duplicate nicknames |
| SPLIT | hex-comma-separated-server-names hex-reason | Remove unreachable servers and their users |
| FORCE | actor target-uid hex-command | Route an action to the target's home server. The actor is an override operator's uid, or a services server reached through the sending link. Commands: `JOIN`/`PART <channels>`, `NICK <nick>`, `ACCOUNT [<name>]`, `UMODE +R`/`-R` |
| INVITED | target-uid hex-folded-channel | Record an invitation on the invitee's home server, which checks its JOINs |
| END | none | Complete the initial state burst |
| PING / PONG | none | Check link liveness |

Initial bursts send servers, users, channel metadata, and memberships, followed
by END. Existing local clients see remote JOINs during a burst. Live state frames
flood the tree except their incoming link. WIRE, FORCE and INVITED follow only the target's
route, avoiding broadcast loops. Client identity prefixes come from session state.
Only `#` channels are shared; `&` channels stay local.

Channel metadata and membership changes use `(revision, revision-server)` order
to resolve concurrent updates deterministically. Revisions start from wall-clock
milliseconds and increase beyond the locally known revision. Partitioned channel
memberships merge on relink; independently granted channel operators are retained.
Nickname collisions keep the lexicographically smaller UID and disconnect the
other user. Recent REMOVE/COLLIDE UIDs are retained for two minutes (up to 8192)
to prevent delayed records from resurrecting disconnected users.

Link loss removes that route's users and downstream servers, announces local
QUITs, and forwards the split to remaining branches. Local users survive. Global
operators can SQUIT a direct peer; it stays disabled locally until CONNECT enables
its configured outgoing connection again. All network state is in memory.
