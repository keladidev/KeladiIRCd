"""Scale check for a running YamIRCd: many idle users at once.

Usage: python -I idle.py HOST PORT [--clients 4000] [--pid PID]

Registers --clients users and leaves them idle (start the server with a large
enough --max-users), then times 200 messages between two members of a small
channel. With --pid, prints the server's memory and thread count before and
after (PowerShell on Windows, /proc on Linux). Finishes within the server's
120-second idle PING, so the idle users never need to answer one.
"""

import argparse
import pathlib
import socket
import subprocess
import time

parser = argparse.ArgumentParser()
parser.add_argument("host")
parser.add_argument("port", type=int)
parser.add_argument("--clients", type=int, default=4000)
parser.add_argument("--pid", type=int)
args = parser.parse_args()


def server_stats():
    if not args.pid:
        return ""
    status = pathlib.Path(f"/proc/{args.pid}/status")
    if status.exists():
        fields = dict(line.split(":", 1) for line in status.read_text().splitlines())
        rss = int(fields["VmRSS"].split()[0]) // 1024
        return f"{rss} MB resident, {fields['Threads'].strip()} threads"
    out = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         f"$p = Get-Process -Id {args.pid}; '{{0}} {{1}}' -f "
         "[int]($p.PrivateMemorySize64 / 1MB), $p.Threads.Count"],
        capture_output=True, text=True,
    ).stdout.split()
    return f"{out[0]} MB private, {out[1]} threads" if len(out) == 2 else ""


def register(nick):
    sock = socket.create_connection((args.host, args.port))
    sock.settimeout(10)
    sock.sendall(f"NICK {nick}\r\nUSER idle 0 * :idle\r\n".encode())
    received = b""
    while b" 376 " not in received and b" 422 " not in received:
        data = sock.recv(65536)
        if not data:
            raise SystemExit(f"{nick} was disconnected: {received[-200:]!r}")
        received += data
    return sock


def drain(sock):
    sock.settimeout(0.2)
    try:
        while sock.recv(65536):
            pass
    except TimeoutError:
        pass
    sock.settimeout(10)


print("Before:", server_stats(), flush=True)
start = time.perf_counter()
idle = [register(f"idle{i}") for i in range(args.clients)]
print(f"Registered {len(idle)} users in {time.perf_counter() - start:.1f}s;",
      server_stats(), flush=True)

sender, receiver = register("sender"), register("receiver")
for sock in (sender, receiver):
    sock.sendall(b"JOIN #idle-probe\r\n")
time.sleep(0.5)
drain(sender)
drain(receiver)
latencies = []
for i in range(200):
    time.sleep(0.02)  # Stay under the server's 100 lines a second flood limit.
    sent = time.perf_counter()
    sender.sendall(f"PRIVMSG #idle-probe :probe-{i}-end\r\n".encode())
    received = b""
    while f"probe-{i}-end".encode() not in received:
        received += receiver.recv(65536)
    latencies.append((time.perf_counter() - sent) * 1000)
latencies.sort()
print(f"Channel message latency ms: p50 {latencies[100]:.2f} "
      f"p99 {latencies[197]:.2f} max {latencies[-1]:.2f}", flush=True)
