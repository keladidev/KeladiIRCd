"""End-to-end check of YamIRCd + Anope (ngircd protocol) with real client sockets.

Usage: python -I anope_e2e.py HOST PORT
"""

import base64
import socket
import sys
import time

HOST, PORT = sys.argv[1], int(sys.argv[2])
failures = []


class Client:
    def __init__(self, nick, sasl=None):
        """Registers `nick`, first logging in with SASL PLAIN if `sasl` is
        (account, password)."""
        self.nick = nick
        self.sock = socket.create_connection((HOST, PORT), timeout=1)
        self.buf = b""
        self.pending = []
        if sasl:
            self.send("CAP REQ sasl")
        self.send(f"NICK {nick}")
        self.send(f"USER {nick} 0 * :{nick} tester")
        self.welcome = []
        if sasl:
            self.welcome += self.wait("ACK :sasl")
            self.send("AUTHENTICATE PLAIN")
            self.welcome += self.wait("AUTHENTICATE +")
            plain = f"\0{sasl[0]}\0{sasl[1]}".encode()
            self.send("AUTHENTICATE " + base64.b64encode(plain).decode())
            self.send("CAP END")
        self.welcome += self.wait(" 376 ")

    def send(self, line):
        print(f"{self.nick} -> {line}")
        self.sock.sendall(line.encode() + b"\r\n")

    def lines(self, seconds):
        """Every line received within `seconds`."""
        deadline, out = time.time() + seconds, self.pending
        self.pending = []
        while time.time() < deadline:
            try:
                data = self.sock.recv(65536)
                if not data:
                    break
                self.buf += data
            except socket.timeout:
                pass
            while b"\r\n" in self.buf:
                line, self.buf = self.buf.split(b"\r\n", 1)
                text = line.decode(errors="replace")
                if text.startswith("PING "):
                    self.sock.sendall(("PONG " + text[5:] + "\r\n").encode())
                    continue
                print(f"  {self.nick} <- {text}")
                out.append(text)
        return out

    def wait(self, needle, seconds=10):
        """Lines up to and including the first one containing `needle`."""
        deadline, seen = time.time() + seconds, []
        while time.time() < deadline:
            batch = self.lines(0.5)
            for i, line in enumerate(batch):
                seen.append(line)
                if needle in line:
                    # Keep the rest of this batch for the next read.
                    self.pending = batch[i + 1:]
                    return seen
        return seen


def check(name, ok):
    print(("PASS " if ok else "FAIL ") + name)
    if not ok:
        failures.append(name)


alice = Client("alice")
alice.send("WHOIS NickServ")
whois = alice.wait(" 318 ")
check("NickServ is visible on the services server",
      any(" 312 alice NickServ services.yamircd.test " in l for l in whois))

alice.send("PRIVMSG NickServ :REGISTER hunter2-secret")
reply = alice.wait("NOTICE alice", 10) + alice.lines(2)
check("NickServ answers REGISTER", any("NickServ" in l and "registered" in l.lower() for l in reply))
check("Registering logs in: account numeric 900", any(" 900 alice " in l for l in reply))
check("Registering sets +R", any("MODE alice :+R" in l for l in reply))
alice.send("WHOIS alice")
whois = alice.wait(" 318 ")
check("WHOIS shows the account (330)", any(" 330 alice alice alice " in l for l in whois))

alice.send("JOIN #room")
alice.wait(" 366 ")
alice.send("PRIVMSG ChanServ :REGISTER #room")
reply = alice.wait("NOTICE alice", 10) + alice.lines(2)
check("ChanServ registers the channel", any("ChanServ" in l and "registered" in l.lower() for l in reply))
check("ChanServ marks the channel registered (+r)", any("MODE #room +r" in l for l in reply))
bob = Client("bob")
bob.send("JOIN #room")
bob.wait(" 366 ")
alice.lines(1)
alice.send("PRIVMSG ChanServ :OP #room bob")
opped = bob.lines(3)
check("ChanServ's MODE reaches channel members",
      any(l.startswith(":ChanServ!") and "MODE #room +o bob" in l for l in opped))

alice.send("PRIVMSG NickServ :LOGOUT")
out = alice.lines(3)
check("LOGOUT logs out (901)", any(" 901 alice " in l for l in out))
check("LOGOUT clears +R", any("MODE alice :-R" in l for l in out))

# Anope 2.1's RECOVER kills the ghost, then moves the caller onto the nickname
# with SVSNICK and logs them in.
alice.send("PRIVMSG NickServ :IDENTIFY hunter2-secret")
alice.lines(3)
bob.send("PRIVMSG NickServ :RECOVER alice hunter2-secret")
recovered = bob.lines(4)
killed = alice.lines(2)
check("RECOVER kills the ghost (KILL)", any("KILL alice :Killed by NickServ" in l for l in killed))
check("RECOVER renames the caller (SVSNICK)", any(l.startswith(":bob!") and "NICK :alice" in l for l in recovered))
check("RECOVER logs the caller in", any(" 900 alice " in l for l in recovered))

# A fresh connection identifies to the registered nickname.
bob.send("QUIT :done")
bob.lines(2)
carol = Client("alice")
carol.lines(3)
carol.send("PRIVMSG NickServ :IDENTIFY hunter2-secret")
ident = carol.lines(4)
check("IDENTIFY logs a new connection in", any(" 900 alice " in l for l in ident))
check("IDENTIFY sets +R", any("MODE alice :+R" in l for l in ident))

# HostServ (alice is a services operator in prepare.py's configuration).
carol.send("PRIVMSG HostServ :SET alice alice.vhost.test")
vhost = carol.lines(3)
check("HostServ SET applies the vhost (396)",
      any(" 396 alice alice.vhost.test " in l for l in vhost))
watcher = Client("watcher")
watcher.send("WHOIS alice")
whois = watcher.wait(" 318 ")
check("Others see the vhost in WHOIS",
      any(" 311 watcher alice ~alice alice.vhost.test " in l for l in whois))

# SASL PLAIN, checked by YamIRCd through Anope's JSON-RPC interface.
dave = Client("dave", sasl=("alice", "hunter2-secret"))
check("SASL PLAIN succeeds (903)", any(" 903 dave " in l for l in dave.welcome))
check("SASL logs in before registration (900)",
      any(" 900 dave " in l and " alice :" in l for l in dave.welcome))
dave.send("PRIVMSG NickServ :LOGOUT")
out = dave.lines(3)
check("Services know the SASL login (LOGOUT answers 901)", any(" 901 dave " in l for l in out))
eve = Client("eve", sasl=("alice", "wrong-password"))
check("SASL with a wrong password fails (904)", any(" 904 eve " in l for l in eve.welcome))
check("A failed SASL client still registers unauthenticated",
      any(" 001 eve " in l for l in eve.welcome))

print()
print("FAILED: " + ", ".join(failures) if failures else "ALL CHECKS PASSED")
sys.exit(1 if failures else 0)
