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

## Operators

Each server has an operator login named `admin`, with its own password in
`.env` (`ALPHA_OPER_SECRET`, `BETA_OPER_SECRET`, `CYPHER_OPER_SECRET`). Connect
to that server and type:

```text
/OPER admin <that server's password>
```

The login only works from `172.30.0.1`, the address users on the Docker host
appear to come from. The class is `override`; change it to `global` in the
`.conf` file for fewer powers.

For OperServ, HostServ `SET` and other services operator commands, set
`SERVICES_ROOT` in `.env` to your nickname and run `docker compose up -d`. Then
register and identify that nickname, and `/OPER`. Anope gives it Services Root
only while it is both identified and an IRC operator, so registering the
nickname alone is not enough.

## What is where

| File | What it sets |
| --- | --- |
| `compose.yaml` | Containers, fixed addresses (`172.30.0.0/24`), published ports |
| `alpha.conf` | Accepts beta, cypher and Anope; SASL and operator rows |
| `beta.conf`, `cypher.conf` | Connect to alpha; SASL and operator rows |
| `keladiircd.Dockerfile` | KeladiIRCd release build |
| `../tools/anope/Dockerfile` | The `network` target builds Anope's configuration (uplink `172.30.0.10`) |
| `.env` | Link, operator and JSON-RPC secrets, and `SERVICES_ROOT` (git ignores it) |

Each container has a fixed address because KeladiIRCd link rows take IP addresses,
not host names. If `172.30.0.0/24` clashes with a network you already use,
change the subnet and every `172.30.0.x` address in `compose.yaml`, the three
`.conf` files and the `UPLINK` build argument together.

## Notes

- **Ports:** they are published on `127.0.0.1` only. To let other machines
  connect, change `127.0.0.1:6667:6667` to `6667:6667` (and likewise for 6668
  and 6669). Put the TLS proxy from [`docs/TLS.md`](../docs/TLS.md) in front
  first, since plain IRC sends passwords in clear text. Users from other
  machines cannot use the operator logins until you add their address (or `*`)
  to the `oper` rows.
- **Client addresses:** users connecting from the Docker host all appear to come
  from the network gateway (`172.30.0.1`). That means they share the limit of 10
  unregistered connections per address.
