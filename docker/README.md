# Docker network: alpha, beta, cypher and Anope

```text
beta   (127.0.0.1:6668) ──┐
                          ├── alpha (127.0.0.1:6667) ── Anope (services.irc.test)
cypher (127.0.0.1:6669) ──┘
```

Three KeladiIRCd servers and Anope 2.1.27 on one private Docker network. beta and
cypher link to alpha, and Anope links to alpha. All three servers offer SASL,
which they check against Anope's JSON-RPC interface on the private network.

## Start it

From this folder:

```sh
cp .env.example .env
```

Edit `.env` and replace every secret. Use only letters, digits, `.`, `_` and `-`.

```sh
docker compose up -d --build
```

The first build compiles Anope from source, which takes a few minutes. Later
builds are cached.

Connect any IRC client, with TLS off, to `127.0.0.1` on one of these ports:

| Server | Port |
| --- | --- |
| alpha | 6667 |
| beta | 6668 |
| cypher | 6669 |

Users on different servers can talk to each other, and NickServ, ChanServ,
HostServ and the other services work from every server.

## Check the links

```sh
docker compose logs beta cypher
docker compose logs anope
```

The beta and cypher logs should show `Link alpha.irc.test connected`. The Anope
log should show alpha, beta and cypher connecting to the network. In a client,
`/links` lists all four servers.

## Stop it

```sh
docker compose down
```

NickServ and ChanServ registrations are kept in the `anope-data` volume. To
delete them as well, run `docker compose down -v`.

## What is where

| File | What it sets |
| --- | --- |
| `compose.yaml` | Containers, fixed addresses (`172.30.0.0/24`), published ports |
| `alpha.conf` | Accepts beta, cypher and Anope; SASL row |
| `beta.conf`, `cypher.conf` | Connect to alpha; SASL row |
| `keladiircd.Dockerfile` | KeladiIRCd release build |
| `../tools/anope/Dockerfile` | The `network` target builds Anope's configuration (uplink `172.30.0.10`) |
| `.env` | Link secrets and the JSON-RPC token (git ignores it) |

Each container has a fixed address because KeladiIRCd link rows take IP addresses,
not host names. If `172.30.0.0/24` clashes with a network you already use,
change the subnet and every `172.30.0.x` address in `compose.yaml`, the three
`.conf` files and the `UPLINK` build argument together.

## Notes

- **Ports:** they are published on `127.0.0.1` only. To let other machines
  connect, change `127.0.0.1:6667:6667` to `6667:6667` (and likewise for 6668
  and 6669). Put the TLS proxy from [`docs/TLS.md`](../docs/TLS.md) in front
  first, since plain IRC sends passwords in clear text.
- **Services root:** none is configured, so HostServ `SET` and OperServ are not
  usable yet. To add one, put an `oper` block in Anope's `services.conf` (see
  `tools/anope/prepare.py --root`). That flag makes the nick root without
  `/OPER`, so register the nick before anyone else can.
- **Client addresses:** users connecting from the Docker host all appear to come
  from the network gateway (`172.30.0.1`). That means they share the limit of 10
  unregistered connections per address.
