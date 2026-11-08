"""Load test for a running YamIRCd: delivery latency and server CPU under load.

Usage: python -I load.py HOST PORT [--clients 250] [--pid PID]

Scenario 1 puts every client in one channel and sends messages at increasing
rates; each message fans out to every other member. Scenario 2 puts every
client in 20 of 250 channels (5000 memberships), which is the costly case for
YamIRCd's per-command state comparison, and measures PING round trips and
messages in those channels. With --pid, the server's CPU time is reported
(needs PowerShell on Windows or /proc on Linux).
"""

import argparse
import pathlib
import selectors
import socket
import statistics
import subprocess
import sys
import time

parser = argparse.ArgumentParser()
parser.add_argument("host")
parser.add_argument("port", type=int)
parser.add_argument("--clients", type=int, default=250)
parser.add_argument("--pid", type=int)
args = parser.parse_args()


def cpu_seconds():
    if not args.pid:
        return None
    proc = pathlib.Path(f"/proc/{args.pid}/stat")
    if proc.exists():
        fields = proc.read_text().split()
        return (int(fields[13]) + int(fields[14])) / 100
    out = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         f"(Get-Process -Id {args.pid}).TotalProcessorTime.TotalSeconds"],
        capture_output=True, text=True,
    ).stdout.strip()
    return float(out) if out else None


class Conn:
    def __init__(self, index):
        self.nick = f"load{index}"
        self.sock = socket.create_connection((args.host, args.port))
        self.sock.setblocking(False)
        self.buf = b""
        self.out = b""

    def queue(self, line):
        self.out += line.encode() + b"\r\n"


sel = selectors.DefaultSelector()
latencies = []
markers = {}  # (nick, marker) -> seen


def pump(conns, seconds, on_line=None):
    """Sends queued output and handles input for `seconds`."""
    end = time.perf_counter() + seconds
    while True:
        for c in conns:
            if c.out:
                try:
                    sent = c.sock.send(c.out)
                    c.out = c.out[sent:]
                except BlockingIOError:
                    pass
        timeout = end - time.perf_counter()
        if timeout <= 0:
            return
        for key, _ in sel.select(min(timeout, 0.05)):
            c = key.data
            try:
                data = c.sock.recv(1 << 16)
            except BlockingIOError:
                continue
            if not data:
                sys.exit(f"{c.nick} was disconnected")
            c.buf += data
            *lines, c.buf = c.buf.split(b"\r\n")
            for raw in lines:
                line = raw.decode(errors="replace")
                if line.startswith("PING "):
                    c.queue("PONG " + line[5:])
                elif on_line:
                    on_line(c, line)


def wait_for(conns, predicate, limit=60):
    end = time.perf_counter() + limit
    while time.perf_counter() < end:
        if predicate():
            return
        pump(conns, 0.05, on_line)
    sys.exit("Timed out waiting for the server")


def on_line(c, line):
    if " 001 " in line:
        markers[(c.nick, "001")] = True
    elif " 366 " in line:
        markers[(c.nick, "366", line.split()[3])] = True
    elif " PONG " in line and ":t=" in line:
        latencies.append((time.perf_counter_ns() - int(line.rsplit("t=", 1)[1])) / 1e6)
    elif " PRIVMSG #" in line and ":t=" in line:
        latencies.append((time.perf_counter_ns() - int(line.rsplit("t=", 1)[1])) / 1e6)


def report(label, started_cpu, started_at):
    if latencies:
        ordered = sorted(latencies)
        p = lambda q: ordered[min(len(ordered) - 1, int(q * len(ordered)))]
        line = (f"{label}: {len(latencies)} deliveries, latency ms "
                f"p50 {p(0.5):.1f} p99 {p(0.99):.1f} max {ordered[-1]:.1f}")
    else:
        line = f"{label}: no deliveries"
    cpu, seconds = cpu_seconds(), time.perf_counter() - started_at
    if cpu is not None and started_cpu is not None:
        line += f", server CPU {100 * (cpu - started_cpu) / seconds:.0f}% of one core"
    print(line, flush=True)


conns = []
start = time.perf_counter()
# Register in batches below the server's per-address limit on unregistered clients.
for batch in range(0, args.clients, 8):
    group = [Conn(i) for i in range(batch, min(batch + 8, args.clients))]
    for c in group:
        sel.register(c.sock, selectors.EVENT_READ, c)
        c.queue(f"NICK {c.nick}")
        c.queue(f"USER load 0 * :load test")
    conns += group
    wait_for(conns, lambda: all((c.nick, "001") in markers for c in group))
print(f"Registered {len(conns)} clients in {time.perf_counter() - start:.1f}s", flush=True)

# Scenario 1: one channel holding everyone.
for c in conns:
    c.queue("JOIN #load")
wait_for(conns, lambda: all((c.nick, "366", "#load") in markers for c in conns))
for rate in (10, 50, 100):
    latencies.clear()
    cpu, started_at, seconds = cpu_seconds(), time.perf_counter(), 5
    interval, next_send, i = 1 / rate, time.perf_counter(), 0
    end = next_send + seconds
    while time.perf_counter() < end:
        while next_send <= time.perf_counter():
            sender = conns[i % len(conns)]
            sender.queue(f"PRIVMSG #load :t={time.perf_counter_ns()}")
            i, next_send = i + 1, next_send + interval
        pump(conns, 0.01, on_line)
    pump(conns, 2, on_line)
    expected = i * (len(conns) - 1)
    report(f"One channel, {rate} msg/s x {len(conns) - 1} recipients "
           f"({len(latencies)}/{expected} delivered)", cpu, started_at)
for c in conns:
    c.queue("PART #load")
pump(conns, 2, on_line)

# Scenario 2: 20 channels each, out of 250, so 5000 memberships.
for n, c in enumerate(conns):
    for k in range(20):
        c.queue(f"JOIN #c{(n + k * 13) % 250}")
wait_for(conns, lambda: sum(1 for key in markers if key[1] == "366") >= len(conns) * 21, 120)
latencies.clear()
cpu, started_at = cpu_seconds(), time.perf_counter()
for round_ in range(20):
    for c in conns[:50]:
        c.queue(f"PING :t={time.perf_counter_ns()}")
    pump(conns, 0.25, on_line)
pump(conns, 2, on_line)
report("PING round trip with 5000 memberships (1000 pings)", cpu, started_at)
latencies.clear()
cpu, started_at = cpu_seconds(), time.perf_counter()
for round_ in range(10):
    for n, c in enumerate(conns):
        c.queue(f"PRIVMSG #c{n % 250} :t={time.perf_counter_ns()}")
    pump(conns, 0.5, on_line)
pump(conns, 2, on_line)
report("Messages in 20-member channels (2500 messages)", cpu, started_at)
