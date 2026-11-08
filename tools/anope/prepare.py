"""Writes an Anope configuration for testing YamIRCd's services link.

Copies Anope's example configuration out of the test image, then changes only
what the tests need: server name, uplink, the "ngircd" protocol module, nickname
length, mail/registration settings so nicknames register without email, the
JSON-RPC interface YamIRCd's SASL uses (httpd on port 8080, rpc_user, a token),
and a services operator `alice` (for HostServ SET).

Usage: python -I prepare.py OUT_DIR [--image IMAGE] [--uplink HOST] [--port PORT]
                            [--password SECRET] [--name SERVICES_NAME]
                            [--rpc-token TOKEN]
"""

import argparse
import io
import pathlib
import subprocess
import tarfile

parser = argparse.ArgumentParser()
parser.add_argument("out", type=pathlib.Path)
parser.add_argument("--image", default="yamircd-test-anope:2.1.27")
parser.add_argument("--uplink", default="host.docker.internal")
parser.add_argument("--port", type=int, default=7000)
parser.add_argument("--password", default="services-secret")
parser.add_argument("--name", default="services.yamircd.test")
parser.add_argument("--rpc-token", default="rpc-secret")
args = parser.parse_args()

archive = subprocess.run(
    ["docker", "run", "--rm", "--entrypoint", "sh", args.image, "-c",
     "cd /anope/conf && tar cf - *.example.conf"],
    check=True, capture_output=True,
).stdout
args.out.mkdir(parents=True, exist_ok=True)
with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
    tar.extractall(args.out, filter="data")

changes = {
    "anope.example.conf": [
        ('value = "services.example.com"', f'value = "{args.name}"'),
        ('host = "127.0.0.1"', f'host = "{args.uplink}"'),
        ("port = 6529", f"port = {args.port}"),
        ('password = "mypassword"', f'password = "{args.password}"'),
        ('module { name = "inspircd" }', 'module { name = "ngircd" }'),
        ("#nicklen = 31", "nicklen = 30"),
        ("usemail = yes", "usemail = no"),
    ],
    "modules.example.conf": [
        ('#module\n{\n\tname = "httpd"', 'module\n{\n\tname = "httpd"'),
        ('#module\n{\n\tname = "jsonrpc"',
         'module\n{\n\tname = "jsonrpc"\n'
         f'\ttoken\n\t{{\n\t\ttoken = "{args.rpc_token}"\n'
         '\t\tmethods = "anope.checkCredentials"\n\t}'),
        ('#module\n{\n\tname = "rpc_user"', 'module\n{\n\tname = "rpc_user"'),
    ],
    "nickserv.example.conf": [
        ("forceemail = yes", "forceemail = no"),
        ('registration = "code"', 'registration = "none"'),
    ],
}
for name, pairs in changes.items():
    path = args.out / name
    text = path.read_text(encoding="utf-8")
    for old, new in pairs:
        if text.count(old) != 1:
            raise SystemExit(f"{name}: expected exactly one {old!r}; has Anope's example changed?")
        text = text.replace(old, new)
    # The main file is loaded as services.conf; the others keep the names it includes.
    if name == "anope.example.conf":
        text += '\noper\n{\n\tname = "alice"\n\ttype = "Services Root"\n\trequire_oper = no\n}\n'
    target = args.out / ("services.conf" if name == "anope.example.conf" else name)
    target.write_text(text, encoding="utf-8", newline="\n")
print(f"Wrote {args.out / 'services.conf'}")
