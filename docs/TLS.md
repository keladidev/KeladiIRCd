# TLS with a proxy

KeladiIRCd has no TLS of its own, so it stays free of dependencies. Put a TLS proxy
in front of it instead. This guide uses [stunnel](https://www.stunnel.org/), which
is small and packaged for every platform; [HAProxy](https://www.haproxy.org/) and
nginx's `stream` module work the same way (examples at the end).

There are three kinds of connection to protect:

| Connection | How |
| --- | --- |
| Clients (port 6697) | stunnel accepts TLS and passes each connection to KeladiIRCd's `--proxy-listen` port with a PROXY header, so KeladiIRCd sees the user's real address |
| Server links | stunnel on both ends: client mode on the connecting server, server mode on the accepting one |
| Anope | Anope connects with TLS itself (`ssl = yes`); stunnel accepts it in front of the link listener |

Everything that KeladiIRCd listens on behind a proxy should listen on `127.0.0.1`
only, so the proxy is the only way in.

## Clients

Without help, every user arriving through a proxy would appear to come from
`127.0.0.1`: the limit of 10 unregistered connections per address would apply to
all of them together, and bans could not tell users apart. So KeladiIRCd has a
separate listener for proxies, `--proxy-listen`. Every connection to it must start
with a [PROXY protocol](https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt)
version 1 line (`PROXY TCP4 <client-ip> <proxy-ip> <client-port> <proxy-port>`);
KeladiIRCd takes the user's address from it and closes connections that lack one.
Anyone who can reach this port can claim any address, so bind it to loopback (or
firewall it to the proxy).

```sh
keladiircd --name irc.example.net \
  --listen 0.0.0.0:6667 \
  --proxy-listen 127.0.0.1:6668
```

Drop `--listen 0.0.0.0:6667` (or use `127.0.0.1:6667`) to accept TLS clients only.

`/etc/stunnel/keladiircd.conf`:

```ini
; Clients: TLS on 6697, plain IRC with a PROXY header to KeladiIRCd.
[irc-clients]
accept = 0.0.0.0:6697
connect = 127.0.0.1:6668
protocol = proxy
cert = /etc/letsencrypt/live/irc.example.net/fullchain.pem
key = /etc/letsencrypt/live/irc.example.net/privkey.pem
sslVersionMin = TLSv1.2
```

`protocol = proxy` is what makes stunnel send the PROXY line. Clients then connect
to `irc.example.net`, port 6697, with TLS on. Reload stunnel after renewing the
certificate (for Let's Encrypt, a `--deploy-hook "systemctl reload stunnel"`).

Check it:

```sh
openssl s_client -connect irc.example.net:6697 -quiet
NICK tester
USER tester 0 * :Tester
WHOIS tester
```

The `311` reply should show your own public address, not `127.0.0.1`.

## Server links

Links already prove the shared secret with a challenge-response handshake, so a
stranger cannot link, but the traffic after it is plain text. Wrap it in TLS with
stunnel on both servers. Here `a.example.net` connects to `b.example.net`.

On **b** (accepting), KeladiIRCd listens for links on loopback only:

```sh
keladiircd --name b.example.net --listen 0.0.0.0:6667 --link-listen 127.0.0.1:7000 --config b.conf
```

```ini
; b.example.net: TLS link port 7001, passed to the local link listener.
[irc-link]
accept = 0.0.0.0:7001
connect = 127.0.0.1:7000
cert = /etc/stunnel/b.example.net.pem
key = /etc/stunnel/b.example.net.key
; Accept only a's certificate.
verifyPeer = yes
CAfile = /etc/stunnel/a.example.net.pem
```

Because the link arrives from stunnel, its address is `127.0.0.1`, so b's link row
names that as a's incoming address:

```text
link a.example.net - 127.0.0.1 KELADIIRCD_LINK_SECRET
```

On **a** (connecting), stunnel runs in client mode and KeladiIRCd connects to it:

```ini
; a.example.net: local port 7101 is a TLS connection to b.
[irc-link-to-b]
client = yes
accept = 127.0.0.1:7101
connect = b.example.net:7001
cert = /etc/stunnel/a.example.net.pem
key = /etc/stunnel/a.example.net.key
verifyChain = yes
CAfile = /etc/stunnel/b.example.net.pem
checkHost = b.example.net
```

```text
link b.example.net 127.0.0.1:7101 127.0.0.1 KELADIIRCD_LINK_SECRET
```

Self-signed certificates are fine for links, since each side pins the other's
certificate (`CAfile`). Make one per server:

```sh
openssl req -x509 -newkey rsa:3072 -nodes -days 3650 \
  -subj "/CN=a.example.net" -addext "subjectAltName=DNS:a.example.net" \
  -keyout a.example.net.key -out a.example.net.pem
```

and copy each server's `.pem` (not its `.key`) to the other.

## Anope

Anope speaks TLS to its uplink itself, through its `ssl_openssl` (or
`ssl_gnutls`) module. Both are "extra" modules that are only built on request.
Install the OpenSSL headers (`libssl-dev` on Debian and Ubuntu), then link the
module into Anope's source before building:

```sh
ln -s extra/ssl_openssl.cpp anope/modules/ssl_openssl.cpp
```

(The test image in `tools/anope` is built without it.) Then:

- In `modules.conf`, enable the `ssl_openssl` block that is already there,
  commented out (`#module` becomes `module`). Its `cert` and `key` are an
  optional client certificate for the uplink. Without those files Anope logs
  `Unable to open certificate conf/fullchain.pem` and connects anyway.
- In `services.conf`, set the uplink's `port` to the stunnel port and
  `ssl = yes`.

On the KeladiIRCd server, stunnel accepts it in front of the link listener,
exactly as for a server link (without `verifyPeer`, unless you give Anope a
client certificate). stunnel then logs `No trusted certificates found`, which is
expected here.


```ini
[anope]
accept = 0.0.0.0:7002
connect = 127.0.0.1:7000
cert = /etc/stunnel/b.example.net.pem
key = /etc/stunnel/b.example.net.key
```

The services row's address becomes `127.0.0.1`, since Anope now arrives through
stunnel:

```text
services services.example.net 127.0.0.1 KELADIIRCD_SERVICES_SECRET
```

If Anope runs on the same machine, it can link to `127.0.0.1:7000` directly and
needs no TLS at all.

SASL passwords travel from KeladiIRCd to Anope's JSON-RPC interface over HTTP. Keep
Anope's httpd on loopback (`ip = "127.0.0.1"` in its `httpd` block) or on a
private network, since Anope's httpd can only add TLS with an SSL module
(`ssl = yes`), which KeladiIRCd's plain HTTP client does not speak.

## HAProxy and nginx

HAProxy, for clients:

```text
frontend irc_tls
    mode tcp
    bind :6697 ssl crt /etc/haproxy/irc.example.net.pem
    default_backend keladiircd

backend keladiircd
    mode tcp
    server local 127.0.0.1:6668 send-proxy
```

The `crt` file holds the certificate chain and the key together
(`cat fullchain.pem privkey.pem > irc.example.net.pem`). `send-proxy` sends
version 1 of the PROXY protocol; do not use `send-proxy-v2`, which KeladiIRCd
does not read.

nginx (`stream` block, outside `http`):

```nginx
stream {
    server {
        listen 6697 ssl;
        ssl_certificate     /etc/letsencrypt/live/irc.example.net/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/irc.example.net/privkey.pem;
        proxy_pass 127.0.0.1:6668;
        proxy_protocol on;
    }
}
```

nginx's `proxy_protocol on` sends version 1. On Debian and Ubuntu the `stream`
module is a separate package, `libnginx-mod-stream`.

## Tested with

Every configuration in this guide was run as written (with self-signed
certificates in place of Let's Encrypt): stunnel 5.68 (Debian 12), HAProxy 2.8
and nginx 1.26 for clients, with the user's real address in WHOIS; stunnel on
both ends of a server link, refusing a certificate other than the pinned one;
and Anope 2.1.27 with `ssl_openssl` linking through stunnel.

## What this does not give you

- IRC clients cannot see whether another user is on TLS; there is no `+z`
  channel mode or `671` WHOIS line.
- Client certificates (CertFP) do not reach KeladiIRCd or Anope, so NickServ's
  certificate login is not available.
- PROXY protocol version 2 (binary) is not supported; use version 1.
