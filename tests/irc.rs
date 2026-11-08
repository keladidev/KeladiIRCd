use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{Shutdown, TcpStream},
    process::{Child, Command, Stdio},
    time::Duration,
};

struct Daemon(Child, Option<std::path::PathBuf>);

impl Daemon {
    fn start(password: Option<&str>) -> (Self, String) {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_yamircd"));
        cmd.args(["--listen", "127.0.0.1:0", "--name", "irc.test"])
            .env_remove("YAMIRCD_PASSWORD")
            .stderr(Stdio::piped());
        if let Some(password) = password {
            cmd.env("YAMIRCD_PASSWORD", password);
        }
        let mut daemon = Self(cmd.spawn().unwrap(), None);
        let mut log = BufReader::new(daemon.0.stderr.take().unwrap());
        let mut line = String::new();
        log.read_line(&mut line).unwrap();
        assert!(line.starts_with("YamIRCd listening on "), "{line}");
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
            std::env::temp_dir().join(format!("yamircd-{}-{unique}.conf", std::process::id()));
        std::fs::write(&path, rows).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_yamircd"))
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
            .env_remove("YAMIRCD_PASSWORD")
            .env("TEST_LINK_SECRET", "link-secret")
            .env("TEST_OPER_SECRET", "oper-secret")
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut log = BufReader::new(child.stderr.take().unwrap());
        let mut line = String::new();
        log.read_line(&mut line).unwrap();
        assert!(line.starts_with("YamIRCd listening on "), "{line}");
        let client_address = line.split_whitespace().nth(3).unwrap().to_string();
        line.clear();
        log.read_line(&mut line).unwrap();
        assert!(line.starts_with("YamIRCd link listener on "), "{line}");
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

    // Reject a caller before disclosing any response or shared link credential.
    let mut rogue = TcpStream::connect(&link_a).unwrap();
    rogue
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    rogue
        .write_all(b"YAMLINK 2 b.test 77726f6e67 622e74657374\r\n")
        .unwrap();
    let mut data = [0; 32];
    assert_eq!(rogue.read(&mut data).unwrap(), 0);

    let mut cyclic = TcpStream::connect(&link_a).unwrap();
    cyclic
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    cyclic
        .write_all(b"YAMLINK 2 b.test 6c696e6b2d736563726574 622e746573742c612e74657374\r\n")
        .unwrap();
    let mut reader = BufReader::new(cyclic);
    let mut greeting = String::new();
    reader.read_line(&mut greeting).unwrap();
    assert!(greeting.starts_with("YAMLINK 2 a.test "));
    assert_eq!(
        reader.read(&mut data).unwrap(),
        0,
        "Cyclic topology was accepted"
    );

    let mut forged = TcpStream::connect(&link_a).unwrap();
    forged
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    forged
        .write_all(b"YAMLINK 2 b.test 6c696e6b2d736563726574 622e74657374\r\n")
        .unwrap();
    let mut reader = BufReader::new(forged.try_clone().unwrap());
    loop {
        let mut line = String::new();
        assert!(reader.read_line(&mut line).unwrap() > 0);
        if line == "END\r\n" {
            break;
        }
    }
    forged
        .write_all(b"USER a.test!1!1 41 61 3132372e302e302e31 - - - - -\r\n")
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

    /// Lines from YamIRCd until a PONG answers this PING, proving nothing else was sent.
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
    assert_eq!(burst[1], "SERVER a.test 1 :YamIRC server");
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
}
