use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    time::Duration,
};

struct Daemon(Child, Option<std::path::PathBuf>);

impl Daemon {
    fn start(password: Option<&str>) -> (Self, String) {
        Self::start_with(password, &[])
    }

    fn start_with(password: Option<&str>, extra: &[&str]) -> (Self, String) {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_keladiircd"));
        cmd.args(["--listen", "127.0.0.1:0", "--name", "irc.test"])
            .args(extra)
            .env_remove("KELADIIRCD_PASSWORD")
            .stderr(Stdio::piped());
        if let Some(password) = password {
            cmd.env("KELADIIRCD_PASSWORD", password);
        }
        let mut daemon = Self(cmd.spawn().unwrap(), None);
        let mut log = BufReader::new(daemon.0.stderr.take().unwrap());
        let mut line = String::new();
        log.read_line(&mut line).unwrap();
        assert!(line.starts_with("KeladiIRCd listening on "), "{line}");
        let address = line.split_whitespace().nth(3).unwrap().to_string();
        std::thread::spawn(move || for _ in log.lines() {});
        (daemon, address)
    }

    fn network(name: &str, rows: &str) -> (Self, String, String) {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("keladiircd-{}-{unique}.conf", std::process::id()));
        std::fs::write(&path, rows).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_keladiircd"))
            .args([
                "--listen",
                "127.0.0.1:0",
                "--name",
                name,
                "--link-listen",
                "127.0.0.1:0",
                "--config",
            ])
            .arg(&path)
            .env_remove("KELADIIRCD_PASSWORD")
            .env("TEST_LINK_SECRET", "link-secret")
            .env("TEST_OPER_SECRET", "oper-secret")
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut log = BufReader::new(child.stderr.take().unwrap());
        let mut line = String::new();
        log.read_line(&mut line).unwrap();
        assert!(line.starts_with("KeladiIRCd listening on "), "{line}");
        let client_address = line.split_whitespace().nth(3).unwrap().to_string();
        line.clear();
        log.read_line(&mut line).unwrap();
        assert!(line.starts_with("KeladiIRCd link listener on "), "{line}");
        let link_address = line.split_whitespace().nth(4).unwrap().to_string();
        std::thread::spawn(move || for _ in log.lines() {});
        (Self(child, Some(path)), client_address, link_address)
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        if let Some(path) = &self.1 {
            let _ = std::fs::remove_file(path);
        }
    }
}

struct Client {
    socket: TcpStream,
    reader: BufReader<TcpStream>,
}

impl Client {
    fn connect(address: &str) -> Self {
        let socket = TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        Self {
            reader: BufReader::new(socket.try_clone().unwrap()),
            socket,
        }
    }

    fn send(&mut self, command: &str) {
        self.socket
            .write_all(format!("{command}\r\n").as_bytes())
            .unwrap();
    }

    fn line(&mut self) -> String {
        let mut line = String::new();
        assert!(
            self.reader.read_line(&mut line).unwrap() > 0,
            "Unexpected disconnect"
        );
        assert!(line.ends_with("\r\n"), "Missing CRLF: {line:?}");
        assert!(line.len() <= 512, "Overlong server output: {}", line.len());
        line.trim_end_matches(['\r', '\n']).into()
    }

    fn until(&mut self, marker: &str) -> Vec<String> {
        let mut lines = Vec::new();
        for _ in 0..100 {
            let line = self.line();
            let done = line.contains(marker);
            lines.push(line);
            if done {
                return lines;
            }
        }
        panic!("No {marker:?} in {lines:?}");
    }

    fn register(&mut self, nick: &str) {
        self.send(&format!("NICK {nick}\r\nUSER guest 0 * :Test User"));
        let welcome = self.until(" 376 ");
        let codes: Vec<_> = welcome
            .iter()
            .take(5)
            .map(|s| s.split_whitespace().nth(1).unwrap())
            .collect();
        assert_eq!(codes, ["001", "002", "003", "004", "005"]);
    }

    fn join(&mut self, channel: &str) {
        self.send(&format!("JOIN {channel}"));
        self.until(" 366 ");
    }

    fn wait_nick(&mut self, nick: &str, present: bool) {
        for _ in 0..50 {
            self.send(&format!("WHOIS {nick}"));
            let replies = self.until(" 318 ");
            if replies.iter().any(|s| s.contains(" 311 ")) == present {
                return;
            }
            std::thread::sleep(Duration::from_millis(40));
        }
        panic!("Nickname {nick} presence did not become {present}");
    }

    fn oper(&mut self, name: &str) {
        self.send(&format!("OPER {name} oper-secret"));
        assert!(self.until(" MODE ").iter().any(|s| s.contains(" 381 ")));
    }
}

/// Connects to a link listener as `name` and answers its challenge using `secret`.
/// Returns the socket, its reader, and the server's final greeting (empty if refused).
fn link_handshake(
    address: &str,
    name: &str,
    secret: &str,
    known: &str,
) -> (TcpStream, BufReader<TcpStream>, String) {
    let hex = |text: &str| -> String { text.bytes().map(|b| format!("{b:02x}")).collect() };
    let mut socket = TcpStream::connect(address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut reader = BufReader::new(socket.try_clone().unwrap());
    let ours = "0123456789abcdef0123456789abcdef";
    socket
        .write_all(format!("KELADILINK 3 {name} {ours} {}\r\n", hex(known)).as_bytes())
        .unwrap();
    let mut challenge = String::new();
    reader.read_line(&mut challenge).unwrap();
    let theirs = challenge
        .trim_end()
        .strip_prefix("CHALLENGE ")
        .expect("Expected a CHALLENGE")
        .to_string();
    let proof = keladiircd::link_proof(secret, "connect", &theirs, ours, name);
    socket
        .write_all(format!("PROOF {proof}\r\n").as_bytes())
        .unwrap();
    let mut hello = String::new();
    if secret == "link-secret" {
        reader.read_line(&mut hello).unwrap();
        // The server's proof shows it knows the secret too.
        let expected = keladiircd::link_proof(secret, "accept", ours, &theirs, "a.test");
        assert!(hello.trim_end().ends_with(&expected), "{hello}");
    }
    (socket, reader, hello)
}

#[test]
fn real_clients_registration_chat_permissions_and_cleanup() {
    let (_daemon, address) = Daemon::start(None);
    let mut alice = Client::connect(&address);
    let mut bob = Client::connect(&address);
    let mut outsider = Client::connect(&address);

    alice.send("JOIN #room");
    assert!(alice.line().contains(" 451 "));
    alice.send("CAP LS 302");
    assert_eq!(
        alice.line(),
        ":irc.test CAP * LS :multi-prefix userhost-in-names"
    );
    alice.send("NICK Alice\r\nUSER alice 0 * :Alice Example\r\nPING :before-cap-end");
    assert_eq!(alice.line(), ":irc.test PONG irc.test :before-cap-end");
    alice.send("CAP REQ :sasl");
    assert_eq!(alice.line(), ":irc.test CAP Alice NAK :sasl");
    alice.send("CAP END");
    let welcome = alice.until(" 376 ");
    assert!(welcome[0].contains(" 001 Alice "));

    bob.send("NICK aLiCe");
    assert!(bob.line().contains(" 433 "));
    bob.register("Bob");
    outsider.register("Eve");
    alice.join("#Room");
    bob.join("#room");
    assert!(alice.line().contains("Bob!~guest@127.0.0.1 JOIN #Room"));

    // TCP fragmentation and a forged source cannot change the delivered identity.
    bob.socket.write_all(b":Alice PRIVMSG #r").unwrap();
    bob.socket.write_all(b"oom :hello Alice\r\n").unwrap();
    assert_eq!(
        alice.line(),
        ":Bob!~guest@127.0.0.1 PRIVMSG #room :hello Alice"
    );
    outsider.send("PRIVMSG #room :external");
    assert!(outsider.line().contains(" 404 "));
    outsider.send("NOTICE #room :external\r\nNOTICE nobody :no errors\r\nPING :silent-notice");
    assert_eq!(outsider.line(), ":irc.test PONG irc.test :silent-notice");
    // Clients send these automatically; ban-list queries need no channel membership.
    outsider.send("MODE #room b");
    assert!(outsider
        .line()
        .ends_with(" 368 Eve #Room :End of channel ban list"));
    // +i is real; +w is accepted silently; +o via MODE is ignored; unknown letters get 501.
    outsider.send("MODE Eve +iw\r\nMODE Eve +o\r\nMODE Eve +x\r\nMODE Eve");
    assert!(outsider.line().ends_with(" MODE Eve :+i"));
    assert!(outsider.line().contains(" 501 Eve "));
    assert!(outsider.line().ends_with(" 221 Eve +i"));

    bob.send("TOPIC #room :unauthorized");
    assert!(bob.line().contains(" 482 "));
    alice.send("TOPIC #room :Welcome!");
    assert!(alice.line().ends_with("TOPIC #Room :Welcome!"));
    assert!(bob.line().ends_with("TOPIC #Room :Welcome!"));
    bob.send("TOPIC #room");
    assert!(bob.line().contains(" 332 Bob #Room :Welcome!"));
    assert!(bob.line().contains(" 333 Bob #Room Alice!"));

    alice.send("MODE #room +o Bob");
    assert!(alice.line().ends_with("MODE #Room +o Bob"));
    assert!(bob.line().ends_with("MODE #Room +o Bob"));
    bob.send("TOPIC #room :");
    assert!(bob.line().ends_with("TOPIC #Room :"));
    assert!(alice.line().ends_with("TOPIC #Room :"));
    bob.send("AWAY :At lunch");
    assert!(bob.line().contains(" 306 "));
    alice.send("PRIVMSG Bob :private hello");
    assert!(bob.line().ends_with("PRIVMSG Bob :private hello"));
    assert!(alice.line().contains(" 301 Alice Bob :At lunch"));
    alice.send("WHOIS Bob");
    let whois = alice.until(" 318 ");
    assert!(whois
        .iter()
        .any(|s| s.contains(" 311 Alice Bob ~guest 127.0.0.1 * :Test User")));
    assert!(whois.iter().any(|s| s.ends_with(" 319 Alice Bob :@#Room")));
    alice.send("USERHOST Bob nobody\r\nISON :bob nobody Alice");
    assert!(alice.line().ends_with(" 302 Alice :Bob=-~guest@127.0.0.1"));
    assert!(alice.line().ends_with(" 303 Alice :Bob Alice"));
    alice.send("NAMES");
    let names = alice.until(" 366 ");
    assert!(names[0].ends_with(" 353 Alice = #Room :@Alice @Bob"));
    assert!(names[1].ends_with(" 366 Alice * :End of /NAMES list"));
    // Alice, Bob and Eve are registered; no operators.
    alice.send("LUSERS");
    let lusers = alice.until(" 266 ");
    assert!(lusers.iter().any(|s| s.contains(" 252 Alice 0 ")));
    assert!(lusers.iter().any(|s| s.contains(" 265 Alice 3 3 ")));
    assert!(lusers.iter().any(|s| s.contains(" 266 Alice 3 3 ")));
    alice.send("WHO #room");
    let who = alice.until(" 315 ");
    assert_eq!(who.iter().filter(|s| s.contains(" 352 ")).count(), 2);

    bob.join("#second");
    alice.join("#second");
    bob.line();
    bob.send("NICK Robert");
    assert!(bob.line().ends_with("NICK :Robert"));
    assert!(alice.line().ends_with("NICK :Robert"));
    // Re-sending the current nickname is silent for the user and channel peers.
    bob.send("NICK Robert\r\nPING :noop-nick");
    assert!(bob.line().ends_with(":noop-nick"));
    alice.send("PING :deduplicated");
    assert!(alice.line().ends_with(":deduplicated"));

    alice.send(&"x".repeat(600));
    assert!(alice.line().contains(" 417 "));
    alice.send("PING :after-long-line");
    assert!(alice.line().ends_with(":after-long-line"));
    alice.send("LIST");
    let list = alice.until(" 323 ");
    assert_eq!(list.iter().filter(|s| s.contains(" 322 ")).count(), 2);

    alice.send("KICK #room Robert :bye");
    assert!(alice.line().ends_with("KICK #Room Robert :bye"));
    assert!(bob.line().ends_with("KICK #Room Robert :bye"));
    bob.send("PART #room");
    assert!(bob.line().contains(" 442 "));
    bob.send("QUIT :done");
    assert_eq!(bob.line(), "ERROR :Closing Link: done");
    assert!(alice.line().ends_with("QUIT :done"));
    outsider.send("NICK Robert\r\nPING :nickname-released");
    assert!(outsider.line().ends_with("NICK :Robert"));
    assert!(outsider.line().ends_with(":nickname-released"));
    alice.send("JOIN 0");
    assert!(alice.line().contains(" PART #Room "));
    assert!(alice.line().contains(" PART #second "));
    alice.send("LIST");
    let list = alice.until(" 323 ");
    assert!(!list.iter().any(|s| s.contains(" 322 ")));

    // An abrupt TCP disconnect must also release the nickname.
    outsider.socket.shutdown(Shutdown::Both).unwrap();
    let mut replacement = Client::connect(&address);
    let mut claimed = false;
    for _ in 0..100 {
        replacement.send("NICK Robert\r\nPING :claim");
        let replies = replacement.until(" PONG ");
        if !replies.iter().any(|s| s.contains(" 433 ")) {
            claimed = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(claimed, "Abrupt disconnect did not release the nickname");
    replacement.send("USER guest 0 * :Replacement");
    assert!(replacement.until(" 376 ")[0].contains(" 001 Robert "));
}

#[test]
fn password_and_invalid_input() {
    let (_daemon, address) = Daemon::start(Some("secret"));
    let mut other = Client::connect(&address);
    other.send("USER guest 0 * :");
    assert!(other.line().contains(" 461 * USER "));
    other.send("USER bad! 0 * :Real Name");
    assert!(other.line().ends_with(" 468 * :Your username is invalid"));
    let mut client = Client::connect(&address);
    client.send("PASS wrong\r\nNICK Guest\r\nUSER guest 0 * :Guest");
    assert!(client.line().contains(" 464 "));
    client.send("JOIN #room");
    assert!(client.line().contains(" 451 "));
    client.send("PASS secret");
    assert!(client.until(" 376 ")[0].contains(" 001 Guest "));
    client.send("PASS secret");
    assert!(client.line().contains(" 462 "));
    client.send("NICK :bad nick");
    assert!(client.line().contains(" 432 "));
    client.send("JOIN #bad,#bad:name");
    client.until(" 366 ");
    assert!(client.line().contains(" 476 "));
    client.send("PRIVMSG");
    assert!(client.line().contains(" 411 "));
    client.send("PRIVMSG Guest :");
    assert!(client.line().contains(" 412 "));
    // UTF8ONLY: invalid lines are rejected without disconnecting.
    client.socket.write_all(b"PRIVMSG Guest :\xff\r\n").unwrap();
    assert_eq!(
        client.line(),
        ":irc.test FAIL PRIVMSG INVALID_UTF8 :Message rejected, use UTF-8"
    );
    client.socket.write_all(&[0xff, b'\r', b'\n']).unwrap();
    assert!(client.line().contains(" FAIL * INVALID_UTF8 "));
    client.send("PING :still-connected");
    assert!(client.line().ends_with(":still-connected"));

    // Three different wrong passwords close the connection; repeating one does not count.
    let mut guesser = Client::connect(&address);
    guesser.send(
        "PASS one
NICK Guesser
USER guest 0 * :Guest",
    );
    assert!(guesser.line().contains(" 464 "));
    guesser.send("PING :same-guess");
    assert!(guesser.line().ends_with(":same-guess"));
    for guess in ["two", "three"] {
        guesser.send(&format!("PASS {guess}"));
        assert!(guesser.line().contains(" 464 "));
    }
    assert_eq!(
        guesser.line(),
        "ERROR :Too many failed authentication attempts"
    );
}

#[test]
fn linked_servers_burst_remote_chat_operator_permissions_and_split() {
    let (mut a, addr_a, link_a) = Daemon::network("a.test", "link b.test - 127.0.0.1 TEST_LINK_SECRET\noper admin 127.0.0.1 override TEST_OPER_SECRET\n");
    let mut alice = Client::connect(&addr_a);
    alice.register("Alice");
    alice.join("#network");
    alice.join("&local");
    alice.send("TOPIC #network :Before linking");
    alice.line();

    // A caller with the wrong secret learns only a nonce, and its proof is refused.
    let (rogue, mut reader, _) = link_handshake(&link_a, "b.test", "wrong-secret", "b.test");
    let mut data = [0; 32];
    assert_eq!(
        reader.read(&mut data).unwrap(),
        0,
        "A wrong proof was accepted"
    );
    rogue.shutdown(Shutdown::Both).unwrap();

    // A correct proof is answered with the server's own proof, then cycles are refused.
    let (_cyclic, mut reader, hello) =
        link_handshake(&link_a, "b.test", "link-secret", "b.test,a.test");
    assert!(hello.starts_with("KELADILINK 3 a.test "), "{hello}");
    assert!(
        !hello.contains("6c696e6b2d736563726574"),
        "The secret crossed the wire"
    );
    assert_eq!(
        reader.read(&mut data).unwrap(),
        0,
        "Cyclic topology was accepted"
    );

    let (mut forged, mut reader, _) = link_handshake(&link_a, "b.test", "link-secret", "b.test");
    loop {
        let mut line = String::new();
        assert!(reader.read_line(&mut line).unwrap() > 0);
        if line == "END\r\n" {
            break;
        }
    }
    forged
        .write_all(b"USER a.test!1!1 41 61 3132372e302e302e31 - - - - - -\r\n")
        .unwrap();
    assert_eq!(
        reader.read(&mut data).unwrap(),
        0,
        "Peer claimed a user owned by the local server"
    );

    let (_b, addr_b, link_b) = Daemon::network("b.test", &format!("link a.test {link_a} 127.0.0.1 TEST_LINK_SECRET\nlink c.test - 127.0.0.1 TEST_LINK_SECRET\noper local 127.0.0.1 local TEST_OPER_SECRET\noper restricted 192.0.2.* global TEST_OPER_SECRET\n"));
    let mut bob = Client::connect(&addr_b);
    bob.register("Bob");
    bob.wait_nick("Alice", true);
    alice.wait_nick("Bob", true);
    bob.send("LIST");
    let list = bob.until(" 323 ");
    assert!(list
        .iter()
        .any(|s| s.contains("#network 1 :Before linking")));
    assert!(!list.iter().any(|s| s.contains("&local")));
    bob.join("#network");
    assert!(alice.until(" JOIN ").last().unwrap().contains("Bob!"));

    alice.send("PRIVMSG Bob :across the link");
    assert!(bob.line().ends_with("PRIVMSG Bob :across the link"));
    bob.send("PRIVMSG #network :channel across the link");
    assert!(alice
        .line()
        .ends_with("PRIVMSG #network :channel across the link"));
    bob.send("NAMES #network");
    let names = bob.until(" 366 ");
    assert!(
        names
            .iter()
            .any(|s| s.contains("@Alice") && s.contains("Bob")),
        "{names:?}"
    );
    alice.send("MODE #network +o Bob");
    alice.line();
    assert!(bob.line().ends_with("MODE #network +o Bob"));
    // Link protocol v2 replicates voice and channel keys to the other server.
    alice.send("MODE #network +vk Bob sesame");
    alice.line();
    assert!(bob.line().ends_with("MODE #network +vk Bob sesame"));
    bob.send("CAP REQ multi-prefix");
    bob.line();
    // The key and the voice travel as separate updates; wait until both arrived.
    let mut replicated = false;
    for _ in 0..50 {
        bob.send("MODE #network\r\nNAMES #network");
        let replies = bob.until(" 366 ");
        if replies[0].ends_with(" 324 Bob #network +ntk sesame")
            && replies
                .iter()
                .any(|s| s.contains(" 353 ") && s.contains("@+Bob"))
        {
            replicated = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(40));
    }
    assert!(
        replicated,
        "Channel key and voice did not reach the other server"
    );
    alice.send("MODE #network -k *");
    alice.line();
    bob.line();
    bob.send("TOPIC #network :Remote topic");
    bob.line();
    assert!(alice.line().ends_with("TOPIC #network :Remote topic"));

    bob.send("KILL Alice :denied");
    assert!(bob.line().contains(" 481 "));
    bob.send("MODE Bob +o\r\nMODE Bob");
    assert!(bob.line().ends_with(" 221 Bob +"));
    bob.send("OPER local wrong");
    assert!(bob.line().contains(" 464 "));
    bob.send("OPER restricted oper-secret");
    assert!(bob.line().contains(" 491 "));
    bob.oper("local");
    bob.send("KILL Alice :remote denied");
    assert!(bob.line().contains(" 481 "));
    bob.send("SAMODE #network -t");
    assert!(bob.line().contains(" 481 "));
    alice.oper("admin");
    alice.send("WALLOPS :network notice");
    assert!(alice.line().ends_with("WALLOPS :network notice"));
    assert!(bob.line().ends_with("WALLOPS :network notice"));
    bob.send("WHOIS Alice");
    assert!(bob.until(" 318 ").iter().any(|s| s.contains(" 313 ")));
    bob.send("WHO Alice");
    assert!(bob
        .until(" 315 ")
        .iter()
        .any(|s| s.contains(" Alice H* :0 ")));

    let (_c, addr_c, _link_c) = Daemon::network(
        "c.test",
        &format!("link b.test {link_b} 127.0.0.1 TEST_LINK_SECRET\n"),
    );
    let mut carol = Client::connect(&addr_c);
    carol.register("Carol");
    carol.wait_nick("Alice", true);
    alice.wait_nick("Carol", true);
    alice.send("SAJOIN Carol #network");
    assert!(carol
        .until(" 366 ")
        .iter()
        .any(|s| s.contains(" JOIN #network")));
    alice.until(" JOIN ");
    bob.until(" JOIN ");
    // More than 15 words used to panic the local server; spaces used to drop the remote link.
    alice.send("SAJOIN Alice :a b c d e f g h i j k l m n o p");
    assert!(alice.line().contains(" 476 "));
    alice.send("SAJOIN Carol :#a #b");
    assert!(alice.line().contains(" 476 "));
    alice.send("SAPART Carol :");
    assert!(alice.line().contains(" 476 "));
    carol.send("PRIVMSG Alice :two hops");
    assert!(alice.line().ends_with("PRIVMSG Alice :two hops"));
    alice.send("PRIVMSG Carol :reply two hops");
    assert!(carol.line().ends_with("PRIVMSG Carol :reply two hops"));
    alice.send("LINKS");
    let links = alice.until(" 365 ");
    assert_eq!(links.iter().filter(|s| s.contains(" 364 ")).count(), 3);

    // The KILL reason is optional.
    alice.send("KILL Bob");
    assert!(bob
        .until("ERROR ")
        .iter()
        .any(|s| s.contains(" KILL Bob :Killed by Alice: No reason given")));
    alice.until(" QUIT ");
    carol.until(" QUIT ");
    alice.wait_nick("Bob", false);
    carol.wait_nick("Bob", false);

    alice.send("SQUIT b.test :maintenance");
    assert!(alice.until(" QUIT ").last().unwrap().contains("Carol"));
    alice.wait_nick("Carol", false);
    carol.wait_nick("Alice", false);
    alice.send("LINKS");
    assert_eq!(
        alice
            .until(" 365 ")
            .iter()
            .filter(|s| s.contains(" 364 "))
            .count(),
        1
    );
    // CONNECT re-enables an incoming-only link after SQUIT; B redials on its own.
    alice.send("CONNECT b.test");
    assert!(alice
        .line()
        .contains("Incoming link accepted again from b.test"));
    assert!(alice
        .until(" JOIN #network")
        .last()
        .unwrap()
        .contains("Carol!"));
    // Users beyond the relinked server see the rejoin too.
    assert!(carol
        .until(" JOIN #network")
        .last()
        .unwrap()
        .contains("Alice!"));
    alice.send("MODE Alice -o");
    assert!(alice.line().ends_with("MODE Alice :-o"));
    alice.send("KILL Alice :denied after deoper");
    assert!(alice.line().contains(" 481 "));
    // Killing A must leave local clients on C alive after the netsplit.
    a.0.kill().unwrap();
    carol.send("PING :still-alive");
    carol.until(":still-alive");
}

#[test]
fn relink_collision_and_unplanned_netsplit() {
    let (mut b, addr_b, link_b) =
        Daemon::network("b.test", "link a.test - 127.0.0.1 TEST_LINK_SECRET\n");
    let mut bob = Client::connect(&addr_b);
    bob.register("Bob");
    bob.join("#merge");
    let (_a, addr_a, _link_a) = Daemon::network("a.test", &format!("link b.test {link_b} 127.0.0.1 TEST_LINK_SECRET\noper admin 127.0.0.1 override TEST_OPER_SECRET\n"));
    let mut alice = Client::connect(&addr_a);
    alice.register("Alice");
    alice.wait_nick("Bob", true);
    bob.wait_nick("Alice", true);
    alice.join("#merge");
    bob.until(" JOIN ");
    alice.oper("admin");
    alice.send("SQUIT b.test :partition");
    alice.until(" QUIT ");
    bob.until(" QUIT ");
    alice.wait_nick("Bob", false);
    bob.wait_nick("Alice", false);
    alice.send("NICK Twin");
    alice.line();
    bob.send("NICK Twin");
    bob.line();
    alice.send("TOPIC #merge :Partition topic");
    alice.line();
    alice.send("CONNECT b.test");
    assert!(alice.line().contains("Link connection enabled"));
    assert_eq!(
        bob.until("ERROR ").last().unwrap(),
        "ERROR :Nickname collision"
    );
    // Collision removal should preserve the authenticated link and winning user.
    let mut observer = Client::connect(&addr_b);
    observer.register("Observer");
    observer.wait_nick("Twin", true);
    observer.send("JOIN #merge");
    let joined = observer.until(" 366 ");
    assert!(joined.iter().any(|s| s.contains("#merge :Partition topic")));
    alice.until(" JOIN ");
    observer.send("PRIVMSG Twin :link survived the collision");
    assert!(alice
        .line()
        .ends_with("PRIVMSG Twin :link survived the collision"));
    b.0.kill().unwrap();
    b.0.wait().unwrap();
    alice.until(" QUIT ");
    alice.wait_nick("Observer", false);
    alice.send("PING :survived abrupt split");
    assert!(alice.line().ends_with(":survived abrupt split"));
    alice.send("KILL Twin :self kill");
    assert!(alice
        .until("ERROR ")
        .iter()
        .any(|s| s.contains(" KILL Twin ")));
    // A self-KILL must not panic while finishing the command or poison server state.
    let mut healthy = Client::connect(&addr_a);
    healthy.register("Healthy");

    // Repeated failed OPER attempts close the connection.
    for _ in 0..2 {
        healthy.send("OPER admin wrong");
        assert!(healthy.line().contains(" 464 "));
    }
    healthy.send("OPER admin wrong");
    assert_eq!(
        healthy.until("ERROR ").last().unwrap(),
        "ERROR :Too many failed authentication attempts"
    );
}

#[test]
fn channel_modes_invites_and_history() {
    let (_daemon, address) = Daemon::start(None);
    let mut op = Client::connect(&address);
    op.register("Op");
    let mut guest = Client::connect(&address);
    guest.register("Guest");
    op.join("#modes");

    op.send("MODE #modes");
    let reply = op.until(" 329 ");
    assert!(reply[0].ends_with(" 324 Op #modes +nt"));
    // Several changes are echoed as one MODE line; bad limits get 696.
    op.send("MODE #modes +ikl sesame 1\r\nMODE #modes +l :abc");
    assert!(op.line().ends_with(" MODE #modes +ikl sesame 1"));
    assert!(op.line().ends_with(" 696 Op #modes l abc :Invalid limit"));
    op.send("MODE #modes +k :has space");
    assert!(op.line().ends_with(" 696 Op #modes k * :Invalid key"));
    guest.send("MODE #modes +m");
    assert!(guest.line().contains(" 482 "));

    // The key is checked first, then invite-only; an invitation overrides +i and +l.
    guest.send("JOIN #modes");
    assert!(guest.line().contains(" 475 Guest #modes "));
    guest.send("JOIN #modes sesame");
    assert!(guest.line().contains(" 473 Guest #modes "));
    op.send("INVITE Guest #modes");
    assert!(op.line().ends_with(" 341 Op Guest #modes"));
    assert!(guest.line().ends_with(" INVITE Guest :#modes"));
    guest.join("#modes sesame");
    op.line();

    // +m allows only voiced users and operators to speak.
    op.send("MODE #modes -ikl *\r\nMODE #modes +m");
    op.line();
    guest.line();
    op.line();
    guest.line();
    guest.send("PRIVMSG #modes :muted");
    assert!(guest.line().contains(" 404 "));
    op.send("MODE #modes +v Guest");
    op.line();
    guest.line();
    guest.send("PRIVMSG #modes :voiced");
    assert!(op.line().ends_with("PRIVMSG #modes :voiced"));

    // Bans block joins, list with 367/368, and unset case-insensitively.
    op.send("MODE #modes +b late");
    op.line();
    guest.line();
    op.send("MODE #modes b");
    assert!(op.line().ends_with(" 367 Op #modes late!*@*"));
    assert!(op.line().contains(" 368 "));
    let mut late = Client::connect(&address);
    late.register("Late");
    late.send("JOIN #modes");
    assert!(late.line().contains(" 474 Late #modes "));
    op.send("MODE #modes -b LATE!*@*");
    op.line();
    guest.line();
    late.join("#modes");
    op.line();
    guest.line();

    // Secret channels are hidden from LIST and WHO for non-members.
    op.send("MODE #modes +s");
    op.line();
    let mut outsider = Client::connect(&address);
    outsider.register("Outsider");
    outsider.send("LIST\r\nWHO #modes");
    let replies = outsider.until(" 315 ");
    assert!(!replies
        .iter()
        .any(|s| s.contains(" 322 ") || s.contains(" 352 ")));

    // Wildcard WHO hides invisible users who share no channel; exact WHO still finds them.
    outsider.send("MODE Outsider +i");
    outsider.line();
    op.send("WHO Outsid*");
    assert_eq!(op.until(" 315 ").len(), 1);
    op.send("WHO Outsider");
    assert_eq!(op.until(" 315 ").len(), 2);

    // WHOWAS remembers users who quit; INFO and TIME answer.
    late.send("QUIT :bye");
    late.until("ERROR ");
    op.send("WHOWAS Late\r\nWHOWAS Nobody");
    let history = op.until(" 369 Op Nobody ");
    assert!(history
        .iter()
        .any(|s| s.ends_with(" 314 Op Late ~guest 127.0.0.1 * :Test User")));
    assert!(history.iter().any(|s| s.contains(" 406 Op Nobody ")));
    op.send("INFO\r\nTIME");
    assert!(op
        .until(" 374 ")
        .iter()
        .all(|s| s.contains(" 371 ") || s.contains(" 374 ")));
    assert!(op.line().contains(" 391 Op irc.test "));
}

/// A fake services server speaking the ngIRCd protocol, as Anope's `ngircd` module does.
struct Services {
    out: TcpStream,
    reader: BufReader<TcpStream>,
}

impl Services {
    fn send(&mut self, lines: &str) {
        self.out
            .write_all(format!("{lines}\r\n").as_bytes())
            .unwrap();
    }

    /// Lines from KeladiIRCd until a PONG answers this PING, proving nothing else was sent.
    fn sync(&mut self) -> Vec<String> {
        self.send(":services.test PING services.test :a.test");
        let mut lines = Vec::new();
        loop {
            let mut line = String::new();
            assert!(
                self.reader.read_line(&mut line).unwrap() > 0,
                "Services link closed"
            );
            let line = line.trim_end().to_string();
            if line == ":a.test PONG a.test :services.test" {
                return lines;
            }
            lines.push(line);
        }
    }
}

#[test]
fn services_link_speaks_ngircd_protocol() {
    let (_a, addr_a, link_a) = Daemon::network(
        "a.test",
        "services services.test 127.0.0.1 TEST_LINK_SECRET\n",
    );
    let mut alice = Client::connect(&addr_a);
    alice.register("Alice");
    alice.join("#room");

    let socket = TcpStream::connect(&link_a).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut services = Services {
        reader: BufReader::new(socket.try_clone().unwrap()),
        out: socket,
    };
    services
        .send("PASS link-secret 0210-IRC+ Anope|2.1:CLHMSo P\r\nSERVER services.test 0 :Services");
    // The handshake and burst introduce this server, its users and channels.
    let burst = services.sync();
    assert!(burst[0].starts_with("PASS link-secret 0210-IRC+ "));
    assert_eq!(burst[1], "SERVER a.test 1 :KeladiIRC server");
    for expected in [
        ":a.test NICK Alice 1 guest 127.0.0.1 1 + :Test User",
        ":Alice JOIN #room",
        ":a.test CHANINFO #room +nt :",
        ":a.test MODE #room +o Alice",
    ] {
        assert!(
            burst.iter().any(|l| l == expected),
            "{expected} not in {burst:?}"
        );
    }

    // A service bot appears as a network user on the services server.
    services.send(":services.test NICK NickServ 1 services services.host 1 +oi :Nickname Services");
    assert!(
        services.sync().is_empty(),
        "The bot was echoed back to services"
    );
    alice.send("WHOIS NickServ");
    let whois = alice.until(" 318 ");
    assert!(whois
        .iter()
        .any(|s| s.contains(" 312 Alice NickServ services.test ")));
    alice.send("PRIVMSG NickServ :help");
    assert_eq!(services.sync(), [":Alice PRIVMSG NickServ :help"]);

    // Logins and +R reach the user, without being echoed to services.
    services.send(":services.test METADATA Alice accountname alice\r\n:NickServ MODE Alice +R\r\n:NickServ NOTICE Alice :You are now identified.");
    assert!(
        services.sync().is_empty(),
        "Login was echoed back to services"
    );
    assert!(alice
        .line()
        .contains(" 900 Alice Alice!~guest@127.0.0.1 alice "));
    assert_eq!(alice.line(), ":services.test MODE Alice :+R");
    assert_eq!(
        alice.line(),
        ":NickServ!~services@services.host NOTICE Alice :You are now identified."
    );

    // A bot in a channel relays its messages once; user mode changes are reported.
    services.send(":NickServ JOIN #room\r\n:NickServ MODE #room +o NickServ");
    assert!(alice.line().ends_with(" JOIN #room"));
    assert!(alice.line().ends_with("MODE #room +o NickServ"));
    alice.send("PRIVMSG #room :hello channel\r\nMODE Alice +i");
    alice.line();
    assert_eq!(
        services.sync(),
        [
            ":Alice PRIVMSG #room :hello channel",
            ":a.test MODE Alice :+i"
        ]
    );

    // ChanServ's +r marks a registered channel; only services may change it.
    services.send(":services.test MODE #room +r");
    assert_eq!(alice.line(), ":services.test MODE #room +r");
    assert!(services.sync().is_empty(), "+r was echoed back to services");
    alice.send("MODE #room -r");
    assert!(alice.line().contains(" 482 Alice #room "));

    // HostServ's vhost replaces the host others see; the user still sees the real one.
    services.send(":services.test METADATA Alice cloakhost :alice.users.test");
    assert!(alice
        .line()
        .contains(" 396 Alice alice.users.test :is now your displayed host"));
    assert!(services.sync().is_empty(), "The vhost was echoed back");
    alice.send("WHOIS Alice");
    let whois = alice.until(" 318 ");
    assert!(whois
        .iter()
        .any(|s| s.contains(" 311 Alice Alice ~guest alice.users.test ")));
    assert!(whois
        .iter()
        .any(|s| s.contains(" 378 Alice Alice :is connecting from *@127.0.0.1 ")));

    // Mode changes and kicks reach services from the user who made them.
    let mut bob = Client::connect(&addr_a);
    bob.register("Bob");
    bob.join("#room");
    alice.send("MODE #room +v Bob\r\nKICK #room Bob :bye");
    alice.until(" KICK ");
    let seen = services.sync();
    for expected in [
        ":Bob JOIN #room",
        ":Alice MODE #room +v Bob",
        ":Alice KICK #room Bob :bye",
    ] {
        assert!(
            seen.iter().any(|l| l == expected),
            "{expected} not in {seen:?}"
        );
    }

    // SVSNICK is reported back as the user's NICK; a services KILL is not echoed.
    services.send(":services.test SVSNICK Alice Guest1");
    assert!(alice.line().ends_with("NICK :Guest1"));
    assert_eq!(services.sync(), [":Alice NICK :Guest1"]);
    services.send(":services.test KILL Guest1 :Enforced");
    assert!(alice
        .until("ERROR ")
        .iter()
        .any(|s| s.contains(" KILL Guest1 :Killed by services.test: Enforced")));
    assert!(
        services.sync().is_empty(),
        "The KILL was echoed back to services"
    );

    // AKILL arrives as GLINE: matching users are removed, and it can be lifted.
    let mut spammer = Client::connect(&addr_a);
    spammer.register("Spammer");
    services.send(":services.test GLINE spammer!*@* 0 :Spam (by OperServ)");
    assert_eq!(
        spammer.until("ERROR ").last().unwrap(),
        "ERROR :Closing Link: Banned (Spam (by OperServ))"
    );
    services.send(":services.test GLINE spammer!*@*");
    services.sync();
    let mut spammer = Client::connect(&addr_a);
    spammer.register("Spammer");

    // Services' users leave the network with the link.
    services.out.shutdown(Shutdown::Both).unwrap();
    let mut watcher = Client::connect(&addr_a);
    watcher.register("Watcher");
    watcher.wait_nick("NickServ", false);
}

#[test]
fn unregistered_connections_per_address_are_limited() {
    let (_daemon, address) = Daemon::start(None);
    let mut pending: Vec<_> = (0..10).map(|_| Client::connect(&address)).collect();
    for client in &mut pending {
        client.send("PING :waiting");
        assert!(client.line().ends_with(":waiting"));
    }
    let mut refused = Client::connect(&address);
    assert_eq!(
        refused.line(),
        "ERROR :Too many unregistered connections from your address"
    );
    // Registering frees the address's slot; registered users do not count.
    pending[0].register("First");
    let mut accepted = Client::connect(&address);
    accepted.register("Second");

    // --max-users caps all connections to the server.
    let (_small, address) = Daemon::start_with(None, &["--max-users", "2"]);
    let mut first = Client::connect(&address);
    first.register("First");
    let mut second = Client::connect(&address);
    second.register("Second");
    assert_eq!(Client::connect(&address).line(), "ERROR :Server is full");
}

/// Tries to register `nick` until it succeeds; false if every attempt was banned.
fn eventually_registers(address: &str, nick: &str) -> bool {
    (0..50).any(|_| {
        let mut client = Client::connect(address);
        client.send(&format!("NICK {nick}\r\nUSER guest 0 * :Guest"));
        let outcome = loop {
            let line = client.line();
            if line.contains(" 001 ") || line.contains(" 465 ") {
                break line;
            }
        };
        let registered = outcome.contains(" 001 ");
        if !registered {
            std::thread::sleep(Duration::from_millis(40));
        }
        registered
    })
}

#[test]
fn server_bans_kline_and_gline() {
    let (_a, addr_a, link_a) = Daemon::network("a.test", "link b.test - 127.0.0.1 TEST_LINK_SECRET\noper admin 127.0.0.1 global TEST_OPER_SECRET\noper helper 127.0.0.1 local TEST_OPER_SECRET\n");
    let (_b, addr_b, _link_b) = Daemon::network(
        "b.test",
        &format!("link a.test {link_a} 127.0.0.1 TEST_LINK_SECRET\n"),
    );
    let mut admin = Client::connect(&addr_a);
    admin.register("Admin");
    admin.oper("admin");
    let mut victim = Client::connect(&addr_b);
    victim.register("Victim");
    admin.wait_nick("Victim", true);

    // Local operators may not ban, and masks matching everyone are refused.
    let mut helper = Client::connect(&addr_a);
    helper.register("Helper");
    helper.oper("helper");
    helper.send("GLINE victim!*@* 0 :nope");
    assert!(helper.line().contains(" 481 "));
    admin.send("GLINE *@* 0 :everyone");
    assert!(admin.line().contains("Invalid or too broad G-Line mask"));

    // A G-Line removes matching users on every server and refuses them afterwards.
    admin.send("GLINE victim!*@* 0 :Go away");
    assert!(admin.line().contains("G-Line added for victim!*@*"));
    assert_eq!(
        victim.until("ERROR ").last().unwrap(),
        "ERROR :Closing Link: Banned (Go away)"
    );
    let mut again = Client::connect(&addr_b);
    again.send("NICK Victim\r\nUSER guest 0 * :Guest");
    assert!(again
        .until("ERROR ")
        .iter()
        .any(|s| s.contains(" 465 Victim :You are banned from this server: Go away")));
    admin.send("STATS g");
    assert!(admin
        .until(" 219 ")
        .iter()
        .any(|s| s.contains(" 223 Admin G victim!*@* 0 Admin!~guest@127.0.0.1 :Go away")));
    admin.send("GLINE victim!*@*");
    assert!(admin.line().contains("G-Line removed for victim!*@*"));
    assert!(
        eventually_registers(&addr_b, "Victim"),
        "UNGLINE did not reach B"
    );

    // A K-Line applies only to the server that set it.
    let mut local = Client::connect(&addr_a);
    local.register("Local");
    admin.send("KLINE local*!*@* 0 :Not here");
    assert!(admin.line().contains("K-Line added for local*!*@*"));
    assert_eq!(
        local.until("ERROR ").last().unwrap(),
        "ERROR :Closing Link: Banned (Not here)"
    );
    let mut elsewhere = Client::connect(&addr_b);
    elsewhere.register("Localb");
    admin.send("STATS k");
    assert!(admin
        .until(" 219 ")
        .iter()
        .any(|s| s.contains(" 216 Admin K local*!*@* 0 ")));

    // Timed bans expire.
    admin.send("GLINE brief!*@* 1 :One second");
    admin.line();
    std::thread::sleep(Duration::from_millis(2100));
    assert!(eventually_registers(&addr_a, "Brief"));
}

/// A stand-in for Anope's JSON-RPC interface: `alice`/`secret` is the only valid
/// login, and requests without the right token (base64, as Anope expects) are refused.
fn fake_anope_rpc() -> String {
    let rpc = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = rpc.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        for stream in rpc.incoming() {
            let mut stream = stream.unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let (mut length, mut authorized) = (0, false);
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let line = line.trim_end();
                if line.is_empty() {
                    break;
                }
                if let Some(value) = line.strip_prefix("Content-Length: ") {
                    length = value.parse().unwrap();
                }
                authorized |= line == "Authorization: Bearer b3Blci1zZWNyZXQ=";
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            let body = String::from_utf8(body).unwrap();
            let json = if !authorized {
                r#"{"jsonrpc":"2.0","error":{"code":-32601,"message":"No authorization"},"id":1}"#
            } else if body
                .contains(r#""method":"anope.checkCredentials","params":["alice","secret"]"#)
            {
                r#"{"jsonrpc":"2.0","result":{"account":"Alice","confirmed":true,"uniqueid":1},"id":1}"#
            } else {
                r#"{"jsonrpc":"2.0","error":{"code":-32098,"message":"Invalid password"},"id":1}"#
            };
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: Close\r\n\r\n{json}",
                json.len()
            );
        }
    });
    address
}

#[test]
fn sasl_plain_logs_in_through_anope_rpc() {
    let rpc = fake_anope_rpc();
    let (_a, address, _link) =
        Daemon::network("a.test", &format!("sasl {rpc} /jsonrpc TEST_OPER_SECRET\n"));
    let mut client = Client::connect(&address);
    client.send("CAP LS 302");
    assert!(client
        .line()
        .ends_with(" CAP * LS :multi-prefix userhost-in-names sasl"));
    client.send("CAP REQ sasl\r\nNICK Alice\r\nUSER alice 0 * :Alice");
    assert!(client.line().ends_with(" ACK :sasl"));

    // A wrong password fails without ending the connection.
    client.send("AUTHENTICATE PLAIN");
    assert_eq!(client.line(), "AUTHENTICATE +");
    client.send("AUTHENTICATE AGFsaWNlAHdyb25n");
    assert!(client
        .line()
        .contains(" 904 Alice :SASL authentication failed"));

    // The right one logs in, and registration waits for the answer.
    client.send("AUTHENTICATE PLAIN");
    assert_eq!(client.line(), "AUTHENTICATE +");
    client.send("AUTHENTICATE AGFsaWNlAHNlY3JldA==\r\nCAP END");
    assert!(client
        .line()
        .contains(" 900 Alice Alice!~alice@127.0.0.1 Alice :You are now logged in as Alice"));
    assert!(client
        .line()
        .contains(" 903 Alice :SASL authentication successful"));
    assert!(client.line().contains(" 001 Alice "));
    client.send("WHOIS Alice");
    assert!(client
        .until(" 318 ")
        .iter()
        .any(|s| s.contains(" 330 Alice Alice Alice ")));
    client.send("AUTHENTICATE PLAIN");
    assert!(client.line().contains(" 907 Alice "));

    // A login that fails while registration waits still lets the client in.
    let mut bob = Client::connect(&address);
    bob.send("CAP REQ sasl\r\nNICK Bob\r\nUSER bob 0 * :Bob\r\nAUTHENTICATE PLAIN");
    bob.until("AUTHENTICATE +");
    bob.send("AUTHENTICATE AGFsaWNlAHdyb25n\r\nCAP END");
    assert!(bob.line().contains(" 904 Bob "));
    assert!(bob.line().contains(" 001 Bob "));

    // Without the sasl row the capability is not offered.
    let (_b, plain, _) = Daemon::network("b.test", "");
    let mut other = Client::connect(&plain);
    other.send("CAP LS");
    assert!(other
        .line()
        .ends_with(" LS :multi-prefix userhost-in-names"));
}

#[test]
fn proxy_listener_takes_the_users_address_from_the_header() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_keladiircd"))
        .args(["--listen", "127.0.0.1:0", "--name", "irc.test"])
        .args(["--proxy-listen", "127.0.0.1:0"])
        .env_remove("KELADIIRCD_PASSWORD")
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut log = BufReader::new(child.stderr.take().unwrap());
    let _daemon = Daemon(child, None);
    let mut line = String::new();
    log.read_line(&mut line).unwrap();
    line.clear();
    log.read_line(&mut line).unwrap();
    assert!(line.starts_with("KeladiIRCd PROXY listener on "), "{line}");
    let proxy = line.split_whitespace().nth(4).unwrap().to_string();
    std::thread::spawn(move || for _ in log.lines() {});

    let mut user = Client::connect(&proxy);
    user.send("PROXY TCP4 203.0.113.7 127.0.0.1 51000 6697");
    user.register("Remote");
    user.send("WHOIS Remote");
    assert!(user
        .until(" 318 ")
        .iter()
        .any(|s| s.contains(" 311 Remote Remote ~guest 203.0.113.7 ")));

    // A connection without the header is closed before it reaches IRC.
    let mut bare = Client::connect(&proxy);
    bare.send("NICK Bare\r\nUSER guest 0 * :Guest");
    let mut data = [0u8; 64];
    // Closed or reset (Windows resets when unread data is discarded), never answered.
    assert!(!matches!(bare.socket.read(&mut data), Ok(n) if n > 0));
}
