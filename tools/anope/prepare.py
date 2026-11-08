"""Writes an Anope configuration for testing YamIRCd's services link.

Copies Anope's example configuration out of the test image, then changes only
what linking needs: server name, uplink, the "ngircd" protocol module, nickname
length, and mail/registration settings so nicknames register without email.

Usage: python -I prepare.py OUT_DIR [--image IMAGE] [--uplink HOST] [--port PORT]
                            [--password SECRET] [--name SERVICES_NAME]
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
    target = args.out / ("services.conf" if name == "anope.example.conf" else name)
    target.write_text(text, encoding="utf-8", newline="\n")
print(f"Wrote {args.out / 'services.conf'}")
