use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    io::{self, Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    sync::{
        mpsc::{self, SyncSender},
        Arc, Mutex, Weak,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// Default limit on connections to this server, registered or not (`--max-users`).
const DEFAULT_MAX_USERS: usize = 256;
/// Unregistered connections from one IP, so idle sockets cannot fill the server.
const MAX_PENDING_PER_IP: usize = 10;
/// Wrong connection passwords or OPER attempts before a connection is closed.
const MAX_AUTH_FAILURES: u8 = 3;
const MAX_CHANNELS: usize = 20;
const MAX_LINE: usize = 510;
const QUEUE_SIZE: usize = 512;
const MAX_WHOWAS: usize = 1024;
/// IRCv3 capabilities offered in CAP LS.
const CAPABILITIES: &str = "multi-prefix userhost-in-names";
mod bans;
mod channel;
mod crypto;
mod network;
mod oper;
mod sasl;
mod services;
use channel::{status_prefix, Channel};
#[doc(hidden)]
pub use crypto::link_proof;
pub use network::LinkConfig;
pub use oper::{OperClass, OperConfig};
pub use sasl::SaslConfig;
pub use services::ServicesConfig;

#[derive(Clone)]
pub struct Config {
    pub listen: String,
    pub name: String,
    /// Shown in LINKS and WHOIS for this server.
    pub description: String,
    pub password: Option<String>,
    pub link_listen: Option<String>,
    /// A client listener for a TLS proxy: each connection starts with a PROXY
    /// protocol v1 header giving the user's real address.
    pub proxy_listen: Option<String>,
    pub links: Vec<LinkConfig>,
    pub opers: Vec<OperConfig>,
    /// Services servers (such as Anope) allowed to link with the ngIRCd protocol.
    pub services: Vec<ServicesConfig>,
    /// Connections this server accepts, registered or not.
    pub max_users: usize,
    /// SASL logins checked against Anope's JSON-RPC interface.
    pub sasl: Option<SaslConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:6667".into(),
            name: "irc.local".into(),
            description: "KeladiIRC server".into(),
            password: None,
            link_listen: None,
            proxy_listen: None,
            links: Vec::new(),
            opers: Vec::new(),
            services: Vec::new(),
            max_users: DEFAULT_MAX_USERS,
            sasl: None,
        }
    }
}

impl Config {
    pub fn validate(&self) -> io::Result<()> {
        if self.name.is_empty()
            || self.name.len() > 63
            || !self
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Server name must be 1-63 ASCII letters, digits, dots or hyphens",
            ));
        }
        if self.description.is_empty()
            || self.description.len() > 100
            || self.description.contains(['\0', '\r', '\n'])
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Server description must be 1-100 bytes on one line",
            ));
        }
        if !(1..=100_000).contains(&self.max_users) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Maximum users must be 1-100000",
            ));
        }
        if self.sasl.as_ref().is_some_and(|s| {
            !s.path.starts_with('/')
                || [&s.address, &s.path, &s.token]
                    .iter()
                    .any(|v| v.is_empty() || v.len() > 200 || v.contains([' ', '\0', '\r', '\n']))
        }) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid sasl configuration",
            ));
        }
        network::validate_config(self)?;
        oper::validate_config(self)?;
        services::validate_config(self)?;
        Ok(())
    }
}

fn fold(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '[' | '{' => '{',
            ']' | '}' => '}',
            '\\' | '|' => '|',
            '^' | '~' => '~',
            _ => c.to_ascii_lowercase(),
        })
        .collect()
}

fn nick_valid(nick: &str) -> bool {
    !nick.is_empty()
        && nick.len() <= 30
        && !nick.as_bytes()[0].is_ascii_digit()
        && nick.as_bytes()[0] != b'-'
        && nick
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"[]{}\\|^~_-`".contains(&b))
}

fn channel_valid(name: &str) -> bool {
    name.len() >= 2
        && name.len() <= 50
        && (name.starts_with('#') || name.starts_with('&'))
        && !name
            .bytes()
            .any(|b| b <= 32 || b == 127 || b",:".contains(&b))
}

#[derive(Debug, Clone)]
struct Message {
    command: String,
    params: Vec<String>,
}

fn parse(line: &str) -> Option<Message> {
    if line.contains(['\0', '\r', '\n']) {
        return None;
    }
    let mut rest = line.trim_start_matches(' ');
    // No tag capabilities are advertised; discard optional untrusted metadata.
    if rest.starts_with('@') {
        rest = rest.split_once(' ')?.1.trim_start_matches(' ');
    }
    // Never trust a client's source: all outgoing sources come from session state.
    if rest.starts_with(':') {
        rest = rest.split_once(' ')?.1.trim_start_matches(' ');
    }
    let (command, tail) = rest.split_once(' ').unwrap_or((rest, ""));
    if command.is_empty() || !command.bytes().all(|b| b.is_ascii_alphabetic()) {
        return None;
    }
    let mut params = Vec::new();
    rest = tail;
    loop {
        rest = rest.trim_start_matches(' ');
        if rest.is_empty() {
            break;
        }
        if params.len() == 15 {
            return None;
        }
        if let Some(trailing) = rest.strip_prefix(':') {
            params.push(trailing.into());
            break;
        }
        let (param, tail) = rest.split_once(' ').unwrap_or((rest, ""));
        params.push(param.into());
        rest = tail;
    }
    Some(Message {
        command: command.to_ascii_uppercase(),
        params,
    })
}

/// Usernames: 1-12 ASCII letters, digits, `_`, `-` or `.`.
fn username_valid(user: &str) -> bool {
    !user.is_empty()
        && user.len() <= 12
        && user
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
}

fn truncate(text: &str, limit: usize) -> &str {
    let mut end = text.len().min(limit);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

struct Client {
    uid: String,
    home: String,
    route: Option<u64>,
    oper: Option<OperClass>,
    nick: String,
    user: String,
    real: String,
    host: String,
    /// Displayed host set by services (HostServ); empty shows the real one.
    cloak: String,
    registered: bool,
    negotiating: bool,
    password: String,
    /// The last rejected PASS value, so repeating it does not count again.
    rejected_password: Option<String>,
    /// Wrong passwords and OPER attempts on this connection.
    auth_failures: u8,
    away: String,
    invisible: bool,
    /// User mode +R: identified to services for the current nickname.
    identified: bool,
    /// Services account name; empty when logged out.
    account: String,
    /// The hidden stand-in for a services server, used as the source of its commands.
    server: bool,
    /// Negotiated IRCv3 capabilities (local clients only).
    multi_prefix: bool,
    userhost_names: bool,
    cap_sasl: bool,
    /// Base64 received so far in a SASL exchange, once a mechanism was chosen.
    sasl: Option<String>,
    /// Waiting for services to check SASL credentials; registration waits too.
    sasl_checking: bool,
    /// Folded names of channels this user was invited to (local clients only).
    invites: BTreeSet<String>,
    tx: SyncSender<String>,
    socket: TcpStream,
    connected: Instant,
    active: Instant,
    ping: Option<Instant>,
}

impl Client {
    /// A client with default state; registration and network code fill in the rest.
    fn new(
        uid: String,
        home: String,
        host: String,
        tx: SyncSender<String>,
        socket: TcpStream,
    ) -> Self {
        Self {
            uid,
            home,
            route: None,
            oper: None,
            nick: String::new(),
            user: String::new(),
            real: String::new(),
            host,
            cloak: String::new(),
            registered: false,
            negotiating: false,
            password: String::new(),
            rejected_password: None,
            auth_failures: 0,
            away: String::new(),
            invisible: false,
            identified: false,
            account: String::new(),
            server: false,
            multi_prefix: false,
            userhost_names: false,
            cap_sasl: false,
            sasl: None,
            sasl_checking: false,
            invites: BTreeSet::new(),
            tx,
            socket,
            connected: Instant::now(),
            active: Instant::now(),
            ping: None,
        }
    }

    fn prefix(&self) -> String {
        if self.server {
            return self.home.clone();
        }
        format!("{}!~{}@{}", self.nick, self.user, self.shown())
    }

    /// The host others see: the services-set vhost, or the real one.
    fn shown(&self) -> String {
        if self.cloak.is_empty() {
            shown_host(&self.host)
        } else {
            shown_host(&self.cloak)
        }
    }

    /// User modes as letters, e.g. `iRo`.
    fn modes(&self) -> String {
        [
            ('i', self.invisible),
            ('o', self.oper.is_some()),
            ('R', self.identified),
        ]
        .iter()
        .filter(|(_, on)| *on)
        .map(|(c, _)| *c)
        .collect()
    }
}

/// An IPv6 host such as `::1` would read as a trailing parameter in replies.
fn shown_host(host: &str) -> String {
    if host.starts_with(':') {
        format!("0{host}")
    } else {
        host.into()
    }
}

/// A user who quit or changed nickname, for WHOWAS.
struct Whowas {
    nick: String,
    user: String,
    host: String,
    real: String,
    server: String,
}

struct Server {
    config: Config,
    clients: BTreeMap<u64, Client>,
    channels: BTreeMap<String, Channel>,
    next_id: u64,
    links: BTreeMap<u64, network::Link>,
    routes: BTreeMap<String, u64>,
    /// Uplink, distance and description of every other server, as seen from here.
    servers: BTreeMap<String, network::ServerInfo>,
    boot: u64,
    disabled_links: BTreeSet<String>,
    handshakes: usize,
    deleted_users: BTreeMap<String, Instant>,
    member_versions: BTreeMap<(String, String), (u64, String)>,
    /// Reasons for kicks made since the last channel sync, by (channel, user).
    kicked: BTreeMap<(String, u64), String>,
    max_local: usize,
    max_global: usize,
    /// Most recent first, capped at MAX_WHOWAS.
    whowas: VecDeque<Whowas>,
    /// KLINEs and GLINEs, including expired ones until the next tick.
    server_bans: Vec<bans::ServerBan>,
    /// This server's own handle, for threads that report back (SASL checks).
    weak: Weak<Mutex<Server>>,
}

impl Server {
    fn new(config: Config) -> Self {
        Self {
            config,
            clients: BTreeMap::new(),
            channels: BTreeMap::new(),
            next_id: 0,
            links: BTreeMap::new(),
            routes: BTreeMap::new(),
            servers: BTreeMap::new(),
            boot: network::millis(),
            disabled_links: BTreeSet::new(),
            handshakes: 0,
            deleted_users: BTreeMap::new(),
            member_versions: BTreeMap::new(),
            kicked: BTreeMap::new(),
            max_local: 0,
            max_global: 0,
            whowas: VecDeque::new(),
            server_bans: Vec::new(),
            weak: Weak::new(),
        }
    }

    /// Records a registered user's identity before it quits or changes nickname.
    fn remember_whowas(&mut self, id: u64) {
        let Some(c) = self.clients.get(&id).filter(|c| c.registered) else {
            return;
        };
        self.whowas.push_front(Whowas {
            nick: c.nick.clone(),
            user: c.user.clone(),
            host: c.shown(),
            real: c.real.clone(),
            server: c.home.clone(),
        });
        self.whowas.truncate(MAX_WHOWAS);
    }

    /// Server description for WHOIS/WHOWAS.
    fn server_info(&self, server: &str) -> &str {
        if server == self.config.name {
            &self.config.description
        } else {
            self.servers
                .get(server)
                .map_or("KeladiIRC server", |s| s.description.as_str())
        }
    }

    /// Users across the network: this server and up to 32 others. Never below the
    /// default, so a small server never refuses (and drops a link over) a remote
    /// user; servers set above the default need the same `--max-users` network-wide.
    pub(crate) fn network_users(&self) -> usize {
        self.config.max_users.max(DEFAULT_MAX_USERS) * 33
    }

    /// Registered (local, network-wide) user counts.
    fn user_counts(&self) -> (usize, usize) {
        let registered = self.clients.values().filter(|c| c.registered);
        let local = registered.clone().filter(|c| c.route.is_none()).count();
        (local, registered.count())
    }

    /// Records peak user counts for LUSERS; call whenever a user is added.
    fn note_peak(&mut self) {
        let (local, global) = self.user_counts();
        self.max_local = self.max_local.max(local);
        self.max_global = self.max_global.max(global);
    }

    fn send(&self, id: u64, line: &str) {
        if let Some(client) = self.clients.get(&id) {
            if let Some(route) = client.route {
                self.link_send(
                    route,
                    &format!(
                        "WIRE {} {}",
                        client.uid,
                        network::encode(truncate(line, MAX_LINE))
                    ),
                );
                return;
            }
            let line = format!("{}\r\n", truncate(line, MAX_LINE));
            // Disconnect a slow client rather than blocking the server or growing memory.
            if client.tx.try_send(line).is_err() {
                let _ = client.socket.shutdown(Shutdown::Both);
            }
        }
    }

    fn numeric(&self, id: u64, code: u16, text: &str) {
        let nick = self
            .clients
            .get(&id)
            .map(|c| c.nick.as_str())
            .filter(|n| !n.is_empty())
            .unwrap_or("*");
        self.send(
            id,
            &format!(":{} {code:03} {nick} {text}", self.config.name),
        );
    }

    fn broadcast(&self, ids: impl IntoIterator<Item = u64>, line: &str) {
        for id in ids {
            self.send(id, line);
        }
    }

    fn peers(&self, id: u64) -> BTreeSet<u64> {
        self.channels
            .values()
            .filter(|c| c.members.contains_key(&id))
            .flat_map(|c| c.members.keys().copied())
            .collect()
    }

    fn find_nick(&self, nick: &str) -> Option<u64> {
        self.clients
            .iter()
            .find(|(_, c)| !c.nick.is_empty() && fold(&c.nick) == fold(nick))
            .map(|(id, _)| *id)
    }

    fn register(&mut self, id: u64) {
        let c = &self.clients[&id];
        if c.registered
            || c.negotiating
            || c.sasl_checking
            || c.nick.is_empty()
            || c.user.is_empty()
        {
            return;
        }
        if self
            .config
            .password
            .as_ref()
            .is_some_and(|p| p != &c.password)
        {
            // Allow PASS to be corrected, but only a few times, and count each new guess once.
            if c.rejected_password.as_ref() != Some(&c.password) {
                let password = c.password.clone();
                self.clients.get_mut(&id).unwrap().rejected_password = Some(password);
                self.numeric(id, 464, ":Password incorrect");
                self.auth_failed(id);
            }
            return;
        }
        if self.reject_banned(id) {
            return;
        }
        self.clients.get_mut(&id).unwrap().registered = true;
        self.note_peak();
        self.numeric(
            id,
            1,
            &format!(":Welcome to KeladiIRC {}", self.clients[&id].prefix()),
        );
        self.numeric(
            id,
            2,
            &format!(
                ":Your host is {}, running version keladiircd-0.1.0",
                self.config.name
            ),
        );
        self.numeric(id, 3, ":This server was created for this session");
        self.numeric(
            id,
            4,
            &format!(
                "{} keladiircd-0.1.0 ioR biklmnorstv bklov",
                self.config.name
            ),
        );
        self.numeric(id, 5, &format!("CASEMAPPING=rfc1459 CHANTYPES=#& CHANMODES=b,k,l,imnrst PREFIX=(ov)@+ MAXLIST=b:{} NICKLEN=30 CHANNELLEN=50 USERLEN=12 TOPICLEN=300 CHANLIMIT=#&:20 NETWORK=KeladiIRC UTF8ONLY :are supported by this server", channel::MAX_BANS));
        self.lusers(id);
        self.motd(id);
        self.net_flood(None, &self.user_record(id));
    }

    fn lusers(&self, id: u64) {
        let (local, count) = self.user_counts();
        let registered = || self.clients.values().filter(|c| c.registered);
        let opers = registered().filter(|c| c.oper.is_some()).count();
        let invisible = registered().filter(|c| c.invisible).count();
        self.numeric(
            id,
            251,
            &format!(
                ":There are {} users and {invisible} invisible on {} servers",
                count - invisible,
                self.routes.len() + 1
            ),
        );
        self.numeric(id, 252, &format!("{opers} :operator(s) online"));
        self.numeric(
            id,
            254,
            &format!("{} :channels formed", self.channels.len()),
        );
        self.numeric(
            id,
            255,
            &format!(":I have {local} clients and {} servers", self.links.len()),
        );
        let (max_local, max_global) = (self.max_local, self.max_global);
        self.numeric(
            id,
            265,
            &format!("{local} {max_local} :Current local users {local}, max {max_local}"),
        );
        self.numeric(
            id,
            266,
            &format!("{count} {max_global} :Current global users {count}, max {max_global}"),
        );
    }

    fn motd(&self, id: u64) {
        self.numeric(
            id,
            375,
            &format!(":- {} Message of the day -", self.config.name),
        );
        self.numeric(id, 372, ":- Welcome to KeladiIRC. Be kind to each other.");
        self.numeric(id, 376, ":End of /MOTD command.");
    }

    /// Splits a space-separated list over several numerics rather than truncating it.
    fn numeric_list(
        &self,
        id: u64,
        code: u16,
        head: &str,
        items: impl IntoIterator<Item = String>,
    ) {
        let mut line = String::new();
        for item in items {
            if !line.is_empty() && line.len() + item.len() + 1 > 350 {
                self.numeric(id, code, &format!("{head} :{line}"));
                line.clear();
            }
            if !line.is_empty() {
                line.push(' ');
            }
            line.push_str(&item);
        }
        if !line.is_empty() {
            self.numeric(id, code, &format!("{head} :{line}"));
        }
    }

    fn names(&self, id: u64, key: &str, requested: &str) {
        self.name_replies(id, key);
        self.numeric(id, 366, &format!("{requested} :End of /NAMES list"));
    }

    fn name_replies(&self, id: u64, key: &str) {
        let Some(ch) = self.channels.get(key).filter(|ch| self.visible(ch, id)) else {
            return;
        };
        let me = &self.clients[&id];
        let names = ch.members.iter().map(|(member, &status)| {
            let c = &self.clients[member];
            let prefix = status_prefix(status, me.multi_prefix);
            if me.userhost_names {
                format!("{prefix}{}", c.prefix())
            } else {
                format!("{prefix}{}", c.nick)
            }
        });
        let symbol = if ch.secret { '@' } else { '=' };
        self.numeric_list(id, 353, &format!("{symbol} {}", ch.name), names);
    }

    fn topic_reply(&self, id: u64, key: &str) {
        let ch = &self.channels[key];
        if ch.topic.is_empty() {
            self.numeric(id, 331, &format!("{} :No topic is set", ch.name));
        } else {
            self.numeric(id, 332, &format!("{} :{}", ch.name, ch.topic));
            self.numeric(
                id,
                333,
                &format!("{} {} {}", ch.name, ch.topic_by, ch.topic_at),
            );
        }
    }

    fn part(&mut self, id: u64, name: &str, reason: &str) {
        let key = fold(name);
        let Some(ch) = self.channels.get(&key) else {
            self.numeric(id, 403, &format!("{name} :No such channel"));
            return;
        };
        if !ch.members.contains_key(&id) {
            self.numeric(id, 442, &format!("{name} :You're not on that channel"));
            return;
        }
        self.broadcast(
            ch.members.keys().copied(),
            &format!(":{} PART {} :{reason}", self.clients[&id].prefix(), ch.name),
        );
        self.remove_member(id, &key);
    }

    /// Counts a wrong password or OPER attempt; too many close the connection.
    fn auth_failed(&mut self, id: u64) {
        let c = self.clients.get_mut(&id).unwrap();
        c.auth_failures += 1;
        if c.auth_failures >= MAX_AUTH_FAILURES {
            self.send(id, "ERROR :Too many failed authentication attempts");
            self.disconnect(id, "Too many failed authentication attempts");
        }
    }

    /// Announces and applies a nickname change; callers check validity and collisions.
    fn change_nick(&mut self, id: u64, nick: &str) {
        if self.clients[&id].registered {
            let mut peers = self.peers(id);
            peers.insert(id);
            self.broadcast(
                peers,
                &format!(":{} NICK :{nick}", self.clients[&id].prefix()),
            );
            self.remember_whowas(id);
        }
        self.clients.get_mut(&id).unwrap().nick = nick.into();
    }

    /// Sets and announces a topic; callers check permissions.
    fn set_topic(&mut self, id: u64, key: &str, text: &str) {
        let prefix = self.clients[&id].prefix();
        let ch = self.channels.get_mut(key).unwrap();
        ch.topic = truncate(text, 300).into();
        ch.topic_by = prefix.clone();
        ch.topic_at = timestamp();
        let ch = &self.channels[key];
        self.broadcast(
            ch.members.keys().copied(),
            &format!(":{prefix} TOPIC {} :{}", ch.name, ch.topic),
        );
    }

    fn remove_member(&mut self, id: u64, key: &str) {
        if let Some(ch) = self.channels.get_mut(key) {
            ch.members.remove(&id);
            if ch.members.is_empty() {
                self.channels.remove(key);
            }
        }
    }

    fn disconnect(&mut self, id: u64, reason: &str) {
        self.remember_whowas(id);
        let Some(c) = self.clients.get(&id) else {
            return;
        };
        let mut peers = self.peers(id);
        peers.remove(&id);
        if c.registered {
            self.broadcast(peers, &format!(":{} QUIT :{reason}", c.prefix()));
            if c.route.is_none() {
                self.net_flood(
                    None,
                    &format!("REMOVE {} {}", c.uid, network::encode(reason)),
                );
            }
        }
        if c.registered && c.route.is_none() {
            let uid = c.uid.clone();
            self.remember_deleted(&uid);
        }
        let keys: Vec<_> = self.channels.keys().cloned().collect();
        for key in keys {
            self.remove_member(id, &key);
        }
        if let Some(c) = self.clients.remove(&id) {
            self.member_versions.retain(|(_, uid), _| uid != &c.uid);
        }
    }

    fn command(&mut self, id: u64, msg: Message) -> bool {
        // These cannot change channel state, and are most of the traffic, so they skip
        // the channel comparison (about 0.5 ms per command at 5000 memberships).
        let channels = !matches!(
            msg.command.as_str(),
            "PRIVMSG"
                | "NOTICE"
                | "PING"
                | "PONG"
                | "WHO"
                | "WHOIS"
                | "WHOWAS"
                | "LIST"
                | "NAMES"
                | "USERHOST"
                | "ISON"
                | "MOTD"
                | "LUSERS"
                | "VERSION"
                | "INFO"
                | "TIME"
                | "STATS"
                | "LINKS"
                | "AWAY"
                | "CAP"
                | "AUTHENTICATE"
        );
        self.replicated(id, channels, |server| server.command_inner(id, msg))
    }

    /// Runs `action` for user `id`, then floods any user state it changed, and any
    /// channel state too when `channels` says the action may change it.
    fn replicated<T>(&mut self, id: u64, channels: bool, action: impl FnOnce(&mut Self) -> T) -> T {
        // shortcut: state is diffed per command to keep replication in one place; it
        // costs O(memberships) per channel-changing command. Use explicit mutation
        // events if networks grow past a few thousand memberships.
        let before_user = self
            .clients
            .get(&id)
            .filter(|c| c.registered)
            .map(|_| self.user_record(id));
        let before_channels = channels.then(|| self.channels.clone());
        let result = action(self);
        if self
            .clients
            .get(&id)
            .is_some_and(|c| c.registered && c.route.is_none())
        {
            let record = self.user_record(id);
            if before_user.is_some_and(|old| old != record) {
                self.net_flood(None, &record);
            }
        }
        if let Some(before) = before_channels {
            self.sync_channels(&before, Some(id));
        }
        result
    }

    fn command_inner(&mut self, id: u64, msg: Message) -> bool {
        let command = msg.command.as_str();
        let p = msg.params;
        if !self.clients.contains_key(&id) {
            return false;
        }
        self.clients.get_mut(&id).unwrap().active = Instant::now();
        if command == "QUIT" {
            let reason = p.first().map(String::as_str).unwrap_or("Client quit");
            self.send(id, &format!("ERROR :Closing Link: {reason}"));
            self.disconnect(id, reason);
            return false;
        }
        if command == "NOTICE" && !self.clients[&id].registered {
            return true;
        }
        if !self.clients[&id].registered
            && !matches!(
                command,
                "CAP" | "PASS" | "NICK" | "USER" | "PING" | "PONG" | "AUTHENTICATE"
            )
        {
            self.numeric(id, 451, ":You have not registered");
            return true;
        }
        let required = match command {
            "NICK" | "PASS" | "PING" | "CAP" | "JOIN" | "PART" | "TOPIC" | "MODE" | "WHOIS" => 1,
            "KICK" | "INVITE" | "OPER" | "SAJOIN" | "SAPART" | "SAMODE" => 2,
            "WALLOPS" | "SQUIT" | "CONNECT" | "USERHOST" | "ISON" | "KILL" | "WHOWAS" => 1,
            "KLINE" | "GLINE" | "AUTHENTICATE" => 1,
            "USER" => 4,
            _ => 0,
        };
        if p.len() < required {
            if command == "NICK" {
                self.numeric(id, 431, ":No nickname given");
            } else {
                self.numeric(id, 461, &format!("{command} :Not enough parameters"));
            }
            return true;
        }
        match command {
            "OPER" => self.oper_login(id, &p),
            "AUTHENTICATE" => self.authenticate(id, &p[0]),
            "KILL" | "WALLOPS" | "SQUIT" | "CONNECT" | "SAJOIN" | "SAPART" | "SAMODE" | "KLINE"
            | "GLINE" => self.oper_command(id, command, &p),
            "LINKS" => {
                self.numeric(
                    id,
                    364,
                    &format!("{0} {0} :0 {1}", self.config.name, self.config.description),
                );
                for name in self.servers_by_distance() {
                    let s = &self.servers[name];
                    self.numeric(
                        id,
                        364,
                        &format!("{name} {} :{} {}", s.uplink, s.hops, s.description),
                    );
                }
                self.numeric(id, 365, "* :End of /LINKS list");
            }
            "CAP" => {
                let offered = if self.config.sasl.is_some() {
                    format!("{CAPABILITIES} sasl")
                } else {
                    CAPABILITIES.into()
                };
                let sub = p[0].to_ascii_uppercase();
                let c = self.clients.get_mut(&id).unwrap();
                if !c.registered && matches!(sub.as_str(), "LS" | "REQ") {
                    c.negotiating = true;
                }
                let reply = match sub.as_str() {
                    "LS" => Some(format!("LS :{offered}")),
                    "LIST" => {
                        let enabled: Vec<_> = [
                            ("multi-prefix", c.multi_prefix),
                            ("userhost-in-names", c.userhost_names),
                            ("sasl", c.cap_sasl),
                        ]
                        .iter()
                        .filter(|(_, on)| *on)
                        .map(|(name, _)| *name)
                        .collect();
                        Some(format!("LIST :{}", enabled.join(" ")))
                    }
                    "REQ" if p.len() > 1 => {
                        // A request is applied only if every capability in it is known.
                        let wanted: Vec<_> = p[1].split(' ').filter(|s| !s.is_empty()).collect();
                        let known = !wanted.is_empty()
                            && wanted.iter().all(|cap| {
                                offered
                                    .split(' ')
                                    .any(|offered| offered == cap.trim_start_matches('-'))
                            });
                        if known {
                            for cap in &wanted {
                                let enable = !cap.starts_with('-');
                                match cap.trim_start_matches('-') {
                                    "multi-prefix" => c.multi_prefix = enable,
                                    "sasl" => c.cap_sasl = enable,
                                    _ => c.userhost_names = enable,
                                }
                            }
                        }
                        let verdict = if known { "ACK" } else { "NAK" };
                        Some(format!("{verdict} :{}", p[1].trim()))
                    }
                    "END" => {
                        c.negotiating = false;
                        None
                    }
                    _ => {
                        self.numeric(id, 410, &format!("{} :Invalid CAP command", p[0]));
                        None
                    }
                };
                if let Some(reply) = reply {
                    let nick = &self.clients[&id].nick;
                    let nick = if nick.is_empty() { "*" } else { nick };
                    self.send(id, &format!(":{} CAP {nick} {reply}", self.config.name));
                }
            }
            "PASS" => {
                if self.clients[&id].registered {
                    self.numeric(id, 462, ":You may not reregister");
                } else {
                    self.clients.get_mut(&id).unwrap().password = p[0].clone();
                }
            }
            "NICK" => {
                if !nick_valid(&p[0]) {
                    self.numeric(id, 432, &format!("{} :Erroneous nickname", p[0]));
                } else if p[0] == self.clients[&id].nick {
                    // An exact no-op change is silent; a case-only change still announces.
                } else if self.find_nick(&p[0]).is_some_and(|other| other != id) {
                    self.numeric(id, 433, &format!("{} :Nickname is already in use", p[0]));
                } else {
                    self.change_nick(id, &p[0]);
                }
            }
            "USER" => {
                if self.clients[&id].registered || !self.clients[&id].user.is_empty() {
                    self.numeric(id, 462, ":You may not reregister");
                } else if p[0].is_empty() || p[3].is_empty() {
                    self.numeric(id, 461, "USER :Not enough parameters");
                } else if !p[0]
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
                {
                    self.numeric(id, 468, ":Your username is invalid");
                } else {
                    let c = self.clients.get_mut(&id).unwrap();
                    c.user = truncate(&p[0], 12).into();
                    c.real = truncate(&p[3], 128).into();
                }
            }
            "PING" => {
                if p[0].is_empty() {
                    self.numeric(id, 409, ":No origin specified");
                } else {
                    self.send(
                        id,
                        &format!(":{} PONG {} :{}", self.config.name, self.config.name, p[0]),
                    );
                }
            }
            "PONG" => {
                if p.last()
                    .is_some_and(|token| token == &format!("keladiircd-{id}"))
                {
                    self.clients.get_mut(&id).unwrap().ping = None;
                }
            }
            "JOIN" => {
                if p[0] == "0" {
                    let names: Vec<_> = self
                        .channels
                        .values()
                        .filter(|c| c.members.contains_key(&id))
                        .map(|c| c.name.clone())
                        .collect();
                    for name in names {
                        self.part(id, &name, "Leaving all channels");
                    }
                } else {
                    let mut keys = p.get(1).map(|k| k.split(','));
                    for name in p[0].split(',') {
                        let key = keys.as_mut().and_then(Iterator::next);
                        self.join_channel(id, name, key, false);
                    }
                }
            }
            "PART" => {
                for name in p[0].split(',') {
                    self.part(
                        id,
                        name,
                        p.get(1)
                            .map(String::as_str)
                            .unwrap_or(&self.clients[&id].nick.clone()),
                    );
                }
            }
            "PRIVMSG" | "NOTICE" => self.message(id, command, &p),
            // Service shortcuts: "/cs register #room" reaches ChanServ as "register #room".
            "NS" | "NICKSERV" | "CS" | "CHANSERV" | "MS" | "MEMOSERV" | "OS" | "OPERSERV"
            | "BS" | "BOTSERV" | "HS" | "HOSTSERV" => {
                let service = match &command[..1] {
                    "N" => "NickServ",
                    "C" => "ChanServ",
                    "M" => "MemoServ",
                    "O" => "OperServ",
                    "B" => "BotServ",
                    _ => "HostServ",
                };
                self.message(id, "PRIVMSG", &[service.to_string(), p.join(" ")]);
            }
            "TOPIC" => {
                let key = fold(&p[0]);
                if let Some(ch) = self.channels.get(&key) {
                    if !ch.members.contains_key(&id) && !self.privileged(id) {
                        self.numeric(id, 442, &format!("{} :You're not on that channel", p[0]));
                    } else if p.len() == 1 {
                        self.topic_reply(id, &key);
                    } else if ch.protected_topic && !ch.is_op(id) && !self.privileged(id) {
                        self.numeric(
                            id,
                            482,
                            &format!("{} :You're not channel operator", ch.name),
                        );
                    } else {
                        self.set_topic(id, &key, &p[1]);
                    }
                } else {
                    self.numeric(id, 403, &format!("{} :No such channel", p[0]));
                }
            }
            "NAMES" => {
                if let Some(targets) = p.first() {
                    for name in targets.split(',') {
                        self.names(id, &fold(name), name);
                    }
                } else {
                    // No argument lists every channel visible to the user.
                    for key in self.channels.keys() {
                        self.name_replies(id, key);
                    }
                    self.numeric(id, 366, "* :End of /NAMES list");
                }
            }
            "LIST" => {
                self.numeric(id, 321, "Channel :Users Name");
                for ch in self.channels.values().filter(|ch| self.visible(ch, id)) {
                    if p.first()
                        .is_none_or(|names| names.split(',').any(|n| fold(n) == fold(&ch.name)))
                    {
                        self.numeric(
                            id,
                            322,
                            &format!("{} {} :{}", ch.name, ch.members.len(), ch.topic),
                        );
                    }
                }
                self.numeric(id, 323, ":End of /LIST");
            }
            "MODE" => self.mode(id, &p),
            "KICK" => self.kick(id, &p),
            "INVITE" => self.invite(id, &p),
            "WHOIS" => {
                for nick in p.last().unwrap().split(',') {
                    if let Some(other) = self
                        .find_nick(nick)
                        .filter(|other| self.clients[other].registered)
                    {
                        let c = &self.clients[&other];
                        self.numeric(
                            id,
                            311,
                            &format!("{} ~{} {} * :{}", c.nick, c.user, c.shown(), c.real),
                        );
                        if !c.cloak.is_empty() && (other == id || self.clients[&id].oper.is_some())
                        {
                            let real = shown_host(&c.host);
                            self.numeric(
                                id,
                                378,
                                &format!("{} :is connecting from *@{real} {real}", c.nick),
                            );
                        }
                        let multi = self.clients[&id].multi_prefix;
                        let channels = self
                            .channels
                            .values()
                            .filter(|ch| self.visible(ch, id))
                            .filter_map(|ch| {
                                let status = *ch.members.get(&other)?;
                                Some(format!("{}{}", status_prefix(status, multi), ch.name))
                            });
                        self.numeric_list(id, 319, &c.nick, channels);
                        self.numeric(
                            id,
                            312,
                            &format!("{} {} :{}", c.nick, c.home, self.server_info(&c.home)),
                        );
                        if c.oper.is_some() {
                            self.numeric(id, 313, &format!("{} :is an IRC operator", c.nick));
                        }
                        if c.identified {
                            self.numeric(
                                id,
                                307,
                                &format!("{} :has identified for this nick", c.nick),
                            );
                        }
                        if !c.account.is_empty() {
                            self.numeric(
                                id,
                                330,
                                &format!("{} {} :is logged in as", c.nick, c.account),
                            );
                        }
                        if !c.away.is_empty() {
                            self.numeric(id, 301, &format!("{} :{}", c.nick, c.away));
                        }
                        self.numeric(
                            id,
                            317,
                            &format!(
                                "{} {} {} :seconds idle, signon time",
                                c.nick,
                                c.active.elapsed().as_secs(),
                                timestamp().saturating_sub(c.connected.elapsed().as_secs())
                            ),
                        );
                    } else {
                        self.numeric(id, 401, &format!("{nick} :No such nick"));
                    }
                    self.numeric(id, 318, &format!("{nick} :End of /WHOIS list"));
                }
            }
            "WHO" => {
                let mask = p.first().map(String::as_str).unwrap_or("*");
                if mask.starts_with(['#', '&']) {
                    if let Some(ch) = self
                        .channels
                        .get(&fold(mask))
                        .filter(|ch| self.visible(ch, id))
                    {
                        for (&other, &status) in &ch.members {
                            self.who_reply(id, other, &ch.name, status);
                        }
                    }
                } else {
                    let all = mask == "*" || mask == "0";
                    let wildcard = all || mask.contains(['*', '?']);
                    let shared = self.peers(id);
                    for (&other, c) in &self.clients {
                        // Invisible users are found only by exact nickname or a shared channel.
                        if c.registered
                            && (all || oper::matches(&fold(mask), &fold(&c.nick)))
                            && (!wildcard || !c.invisible || other == id || shared.contains(&other))
                        {
                            self.who_reply(id, other, "*", 0);
                        }
                    }
                }
                self.numeric(id, 315, &format!("{mask} :End of /WHO list"));
            }
            "WHOWAS" => {
                // A count of zero or less means all entries.
                let count = p
                    .get(1)
                    .and_then(|n| n.parse::<i64>().ok())
                    .filter(|n| *n > 0)
                    .map_or(usize::MAX, |n| n as usize);
                for nick in p[0].split(',') {
                    let entries: Vec<_> = self
                        .whowas
                        .iter()
                        .filter(|w| fold(&w.nick) == fold(nick))
                        .take(count)
                        .collect();
                    if entries.is_empty() {
                        self.numeric(id, 406, &format!("{nick} :There was no such nickname"));
                    }
                    for w in entries {
                        self.numeric(
                            id,
                            314,
                            &format!("{} ~{} {} * :{}", w.nick, w.user, w.host, w.real),
                        );
                        self.numeric(
                            id,
                            312,
                            &format!("{} {} :{}", w.nick, w.server, self.server_info(&w.server)),
                        );
                    }
                    self.numeric(id, 369, &format!("{nick} :End of WHOWAS"));
                }
            }
            "INFO" => {
                for line in [
                    "KeladiIRCd 0.1.0, a small standalone IRC daemon written in Rust.",
                    "Released under the MIT license.",
                ] {
                    self.numeric(id, 371, &format!(":{line}"));
                }
                self.numeric(id, 374, ":End of INFO list");
            }
            "TIME" => {
                let now = timestamp();
                self.numeric(
                    id,
                    391,
                    &format!("{} {now} 0 :{}", self.config.name, utc(now)),
                );
            }
            "AWAY" => {
                let text = p.first().map(String::as_str).unwrap_or("");
                self.clients.get_mut(&id).unwrap().away = truncate(text, 200).into();
                self.numeric(
                    id,
                    if text.is_empty() { 305 } else { 306 },
                    if text.is_empty() {
                        ":You are no longer marked as being away"
                    } else {
                        ":You have been marked as being away"
                    },
                );
            }
            "USERHOST" | "ISON" => {
                // Accept both separate parameters and one space-separated trailing list.
                let found: Vec<_> = p
                    .iter()
                    .flat_map(|s| s.split(' '))
                    .take(if command == "USERHOST" { 5 } else { usize::MAX })
                    .filter_map(|nick| self.find_nick(nick))
                    .filter(|other| self.clients[other].registered)
                    .map(|other| {
                        let c = &self.clients[&other];
                        if command == "ISON" {
                            return c.nick.clone();
                        }
                        format!(
                            "{}{}={}~{}@{}",
                            c.nick,
                            if c.oper.is_some() { "*" } else { "" },
                            if c.away.is_empty() { '+' } else { '-' },
                            c.user,
                            c.shown()
                        )
                    })
                    .collect();
                let code = if command == "USERHOST" { 302 } else { 303 };
                self.numeric(id, code, &format!(":{}", found.join(" ")));
            }
            "MOTD" => self.motd(id),
            "STATS" => self.stats(id, &p),
            "LUSERS" => self.lusers(id),
            "VERSION" => self.numeric(
                id,
                351,
                &format!(
                    "keladiircd-0.1.0 {} :Rust standalone IRC daemon",
                    self.config.name
                ),
            ),
            _ => self.numeric(id, 421, &format!("{command} :Unknown command")),
        }
        if self.clients.contains_key(&id) {
            self.register(id);
            true
        } else {
            false
        }
    }

    fn who_reply(&self, id: u64, other: u64, channel: &str, status: u8) {
        let c = &self.clients[&other];
        self.numeric(
            id,
            352,
            &format!(
                "{channel} ~{} {} {} {} {}{}{} :0 {}",
                c.user,
                c.shown(),
                c.home,
                c.nick,
                if c.away.is_empty() { "H" } else { "G" },
                if c.oper.is_some() { "*" } else { "" },
                status_prefix(status, self.clients[&id].multi_prefix),
                c.real
            ),
        );
    }

    fn message(&self, id: u64, command: &str, p: &[String]) {
        let notice = command == "NOTICE";
        if p.is_empty() || p[0].is_empty() {
            if !notice {
                self.numeric(id, 411, &format!(":No recipient given ({command})"));
            }
            return;
        }
        if p.len() < 2 || p[1].is_empty() {
            if !notice {
                self.numeric(id, 412, ":No text to send");
            }
            return;
        }
        let mut seen = BTreeSet::new();
        for target in p[0].split(',') {
            if !seen.insert(fold(target)) {
                continue;
            }
            let line = format!(
                ":{} {command} {target} :{}",
                self.clients[&id].prefix(),
                p[1]
            );
            if target.starts_with(['#', '&']) {
                if let Some(ch) = self.channels.get(&fold(target)) {
                    let status = ch.members.get(&id);
                    // +n blocks non-members; +m blocks everyone without voice or op.
                    // Services may always speak.
                    if !self.privileged(id)
                        && ((ch.no_external && status.is_none())
                            || (ch.moderated && status.is_none_or(|s| *s == 0)))
                    {
                        if !notice {
                            self.numeric(id, 404, &format!("{target} :Cannot send to channel"));
                        }
                    } else {
                        self.broadcast(
                            ch.members.keys().copied().filter(|other| *other != id),
                            &line,
                        );
                    }
                } else if !notice {
                    self.numeric(id, 403, &format!("{target} :No such channel"));
                }
            } else if let Some(other) = self
                .find_nick(target)
                .filter(|other| self.clients[other].registered)
            {
                self.send(other, &line);
                if !notice && !self.clients[&other].away.is_empty() {
                    self.numeric(id, 301, &format!("{target} :{}", self.clients[&other].away));
                }
            } else if !notice {
                self.numeric(id, 401, &format!("{target} :No such nick"));
            }
        }
    }

    fn mode(&mut self, id: u64, p: &[String]) {
        if !p[0].starts_with(['#', '&']) {
            if fold(&p[0]) != fold(&self.clients[&id].nick) {
                self.numeric(id, 502, ":Cannot change mode for other users");
            } else if p.len() == 1 {
                self.numeric(id, 221, &format!("+{}", self.clients[&id].modes()));
            } else {
                let (mut adding, mut unknown, mut applied) = (true, false, String::new());
                for mode in p[1].chars() {
                    let c = self.clients.get_mut(&id).unwrap();
                    match mode {
                        '+' => adding = true,
                        '-' => adding = false,
                        // RFC 2812: a client setting +o on itself is ignored; only OPER grants it.
                        'o' => {
                            if !adding && c.oper.take().is_some() {
                                channel::push_mode(&mut applied, false, 'o');
                            }
                        }
                        'i' => {
                            if c.invisible != adding {
                                c.invisible = adding;
                                channel::push_mode(&mut applied, adding, 'i');
                            }
                        }
                        // shortcut: +w is accepted without effect because WALLOPS always reach
                        // every operator; add a wallops opt-in if users need one.
                        'w' => {}
                        _ => unknown = true,
                    }
                }
                if !applied.is_empty() {
                    let c = &self.clients[&id];
                    self.send(id, &format!(":{} MODE {} :{applied}", c.prefix(), c.nick));
                }
                if unknown {
                    self.numeric(id, 501, ":Unknown MODE flag");
                }
            }
            return;
        }
        self.channel_mode(id, p);
    }

    fn kick(&mut self, id: u64, p: &[String]) {
        let key = fold(&p[0]);
        let Some(ch) = self.channels.get(&key) else {
            self.numeric(id, 403, &format!("{} :No such channel", p[0]));
            return;
        };
        if !ch.members.contains_key(&id) && !self.privileged(id) {
            self.numeric(id, 442, &format!("{} :You're not on that channel", p[0]));
            return;
        }
        if !ch.is_op(id) && !self.privileged(id) {
            self.numeric(id, 482, &format!("{} :You're not channel operator", p[0]));
            return;
        }
        for nick in p[1].split(',') {
            let Some(other) = self.find_nick(nick) else {
                self.numeric(id, 401, &format!("{nick} :No such nick"));
                continue;
            };
            let Some(ch) = self.channels.get(&key) else {
                break;
            };
            if !ch.members.contains_key(&other) {
                self.numeric(
                    id,
                    441,
                    &format!("{nick} {} :They aren't on that channel", p[0]),
                );
                continue;
            }
            let reason = p
                .get(2)
                .filter(|r| !r.is_empty())
                .unwrap_or(&self.clients[&id].nick)
                .clone();
            self.broadcast(
                ch.members.keys().copied(),
                &format!(
                    ":{} KICK {} {} :{reason}",
                    self.clients[&id].prefix(),
                    ch.name,
                    self.clients[&other].nick,
                ),
            );
            self.remove_member(other, &key);
            self.kicked.insert((key.clone(), other), reason);
            if other == id {
                break;
            }
        }
    }

    fn tick(&mut self) {
        self.prune_server_bans();
        let now = Instant::now();
        self.deleted_users
            .retain(|_, at| now.duration_since(*at) < Duration::from_secs(120));
        let mut expired = Vec::new();
        for (&id, c) in &self.clients {
            if c.route.is_some() {
                continue;
            }
            if (!c.registered && now.duration_since(c.connected) >= Duration::from_secs(60))
                || c.ping
                    .is_some_and(|sent| now.duration_since(sent) >= Duration::from_secs(60))
            {
                expired.push(id);
            }
        }
        for id in expired {
            // The writer sends this ERROR, then closes the connection.
            self.send(id, "ERROR :Connection timed out");
            self.disconnect(id, "Connection timed out");
        }
        let idle: Vec<_> = self
            .clients
            .iter()
            .filter(|(_, c)| {
                c.route.is_none()
                    && c.registered
                    && c.ping.is_none()
                    && now.duration_since(c.active) >= Duration::from_secs(120)
            })
            .map(|(&id, _)| id)
            .collect();
        for id in idle {
            self.send(id, &format!("PING :keladiircd-{id}"));
            self.clients.get_mut(&id).unwrap().ping = Some(now);
        }
    }
}

fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// `YYYY-MM-DD HH:MM:SS UTC` for a Unix timestamp (Hinnant's civil-from-days).
fn utc(secs: u64) -> String {
    let (days, rem) = ((secs / 86_400) as i64 + 719_468, secs % 86_400);
    let (era, doe) = (days.div_euclid(146_097), days.rem_euclid(146_097));
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Serve TCP clients forever; per-connection errors drop only that connection.
/// Callers choose the listening address.
pub fn serve(listener: TcpListener, config: Config) -> io::Result<()> {
    config.validate()?;
    // ponytail: one state lock and two threads/client, capped at 256 connections;
    // move to an async event loop if this standalone server needs larger scale.
    let server = Arc::new(Mutex::new(Server::new(config)));
    server.lock().unwrap().weak = Arc::downgrade(&server);
    network::start(Arc::clone(&server))?;
    if let Some(address) = server.lock().unwrap().config.proxy_listen.clone() {
        let proxy = TcpListener::bind(&address)?;
        eprintln!("KeladiIRCd PROXY listener on {}", proxy.local_addr()?);
        let server = Arc::clone(&server);
        thread::spawn(move || {
            for stream in proxy.incoming().flatten() {
                // Its own thread, so a proxy slow to send the header delays no one else.
                let server = Arc::clone(&server);
                thread::spawn(move || {
                    if let Err(err) = accept(&server, stream, true) {
                        eprintln!("Proxied connection dropped during setup: {err}");
                    }
                });
            }
        });
    }
    let weak = Arc::downgrade(&server);
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(1));
        let Some(server) = weak.upgrade() else {
            break;
        };
        server.lock().unwrap().tick();
    });
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(err) = accept(&server, stream, false) {
                    eprintln!("Client connection dropped during setup: {err}");
                }
            }
            Err(err) => {
                eprintln!("Accept failed: {err}");
                // Avoid spinning while out of file descriptors or similar.
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
    Ok(())
}

/// Reads a PROXY protocol v1 header, `PROXY TCP4|TCP6 <src> <dst> <sport> <dport>`
/// (or `PROXY UNKNOWN ...`), one byte at a time so no client data is consumed.
/// Returns the user's address, or None for UNKNOWN (a proxy health check).
fn proxy_header(stream: &mut TcpStream) -> io::Result<Option<String>> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "Bad PROXY header");
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut header = Vec::new();
    let mut byte = [0u8];
    while header.last() != Some(&b'\n') {
        if header.len() >= 107 || stream.read(&mut byte)? == 0 {
            return Err(invalid());
        }
        header.push(byte[0]);
    }
    let header = std::str::from_utf8(&header).map_err(|_| invalid())?;
    let p: Vec<_> = header.trim_end().split(' ').collect();
    match p.as_slice() {
        ["PROXY", "UNKNOWN", ..] => Ok(None),
        ["PROXY", "TCP4" | "TCP6", source, _, _, _] => {
            let ip: std::net::IpAddr = source.parse().map_err(|_| invalid())?;
            Ok(Some(ip.to_string()))
        }
        _ => Err(invalid()),
    }
}

fn accept(server: &Arc<Mutex<Server>>, mut stream: TcpStream, proxied: bool) -> io::Result<()> {
    let host = if proxied {
        match proxy_header(&mut stream)? {
            Some(host) => host,
            None => return Ok(()),
        }
    } else {
        stream.peer_addr()?.ip().to_string()
    };
    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    stream.set_nodelay(true)?;
    // Clone before registering the client so a failure leaves no half-made session.
    let socket = stream.try_clone()?;
    let mut writer = stream.try_clone()?;
    let (tx, rx) = mpsc::sync_channel(QUEUE_SIZE);
    let id;
    {
        let mut state = server.lock().unwrap();
        let local = state.clients.values().filter(|c| c.route.is_none());
        let pending = local
            .clone()
            .filter(|c| !c.registered && c.host == host)
            .count();
        let refusal = if local.count() >= state.config.max_users {
            Some("ERROR :Server is full\r\n")
        } else if pending >= MAX_PENDING_PER_IP {
            Some("ERROR :Too many unregistered connections from your address\r\n")
        } else {
            None
        };
        if let Some(refusal) = refusal {
            drop(state);
            let _ = stream.write_all(refusal.as_bytes());
            return Ok(());
        }
        state.next_id += 1;
        id = state.next_id;
        let home = state.config.name.clone();
        let uid = format!("{home}!{}!{id}", state.boot);
        state
            .clients
            .insert(id, Client::new(uid, home, host, tx, socket));
    }
    let write_state = Arc::clone(server);
    thread::spawn(move || {
        for line in rx {
            if writer.write_all(line.as_bytes()).is_err() {
                break;
            }
        }
        write_state
            .lock()
            .unwrap()
            .disconnect(id, "Connection closed");
        // Graceful close: send FIN, then briefly drain input, so a line the client sent
        // after QUIT does not turn the close into a TCP reset that discards our ERROR.
        let _ = writer.shutdown(Shutdown::Write);
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut sink = [0_u8; 512];
        while Instant::now() < deadline && writer.read(&mut sink).is_ok_and(|n| n > 0) {}
        let _ = writer.shutdown(Shutdown::Both);
    });
    let read_state = Arc::clone(server);
    thread::spawn(move || {
        let mut buffer = [0_u8; 1024];
        let mut line = Vec::new();
        let mut oversized = false;
        let mut burst = Instant::now();
        let mut commands = 0;
        let mut reason = "Connection closed";
        'connection: loop {
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    for &byte in &buffer[..n] {
                        if byte != b'\n' {
                            if line.len() < MAX_LINE + 1 {
                                line.push(byte);
                            } else {
                                oversized = true;
                            }
                            continue;
                        }
                        if burst.elapsed() >= Duration::from_secs(1) {
                            burst = Instant::now();
                            commands = 0;
                        }
                        commands += 1;
                        if commands > 100 {
                            read_state.lock().unwrap().send(id, "ERROR :Excess flood");
                            reason = "Excess flood";
                            break 'connection;
                        }
                        if line.last() == Some(&b'\r') {
                            line.pop();
                        }
                        let mut state = read_state.lock().unwrap();
                        if !state.clients.contains_key(&id) {
                            break 'connection;
                        }
                        if oversized || line.len() > MAX_LINE {
                            state.numeric(id, 417, ":Input line was too long");
                        } else if let Ok(text) = std::str::from_utf8(&line) {
                            if let Some(msg) = parse(text) {
                                if !state.command(id, msg) {
                                    break 'connection;
                                }
                            }
                        } else {
                            // UTF8ONLY: reject only this line, as the IRCv3 spec recommends.
                            let command = parse(&String::from_utf8_lossy(&line))
                                .map_or_else(|| "*".into(), |m| m.command);
                            let reply = format!(
                                ":{} FAIL {command} INVALID_UTF8 :Message rejected, use UTF-8",
                                state.config.name
                            );
                            state.send(id, &reply);
                        }
                        line.clear();
                        oversized = false;
                    }
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    if !read_state.lock().unwrap().clients.contains_key(&id) {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        read_state.lock().unwrap().disconnect(id, reason);
        // The writer drains queued replies (including ERROR) before closing.
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_and_ping_timeouts() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let _remote = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (socket, _) = listener.accept().unwrap();
        let (tx, rx) = mpsc::sync_channel(QUEUE_SIZE);
        let mut server = Server::new(Config::default());
        let mut client = Client::new(
            "irc.local!1!1".into(),
            "irc.local".into(),
            "127.0.0.1".into(),
            tx,
            socket,
        );
        (client.nick, client.user, client.real) = ("Guest".into(), "guest".into(), "Guest".into());
        client.registered = true;
        client.active = Instant::now() - Duration::from_secs(121);
        server.clients.insert(1, client);
        server.tick();
        assert_eq!(rx.try_recv().unwrap(), "PING :keladiircd-1\r\n");
        assert!(server.clients[&1].ping.is_some());
        server.command(1, parse("PONG :wrong-token").unwrap());
        assert!(server.clients[&1].ping.is_some());
        server.command(1, parse("PONG :keladiircd-1").unwrap());
        assert!(server.clients[&1].ping.is_none());
        server.tick();
        assert!(rx.try_recv().is_err());

        let client = server.clients.get_mut(&1).unwrap();
        client.ping = Some(Instant::now() - Duration::from_secs(61));
        server.tick();
        assert_eq!(rx.try_recv().unwrap(), "ERROR :Connection timed out\r\n");
        assert!(server.clients.is_empty());

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let _remote = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (socket, _) = listener.accept().unwrap();
        let (tx, rx) = mpsc::sync_channel(QUEUE_SIZE);
        let mut client = Client::new(
            "irc.local!1!2".into(),
            "irc.local".into(),
            "127.0.0.1".into(),
            tx,
            socket,
        );
        client.negotiating = true;
        client.connected = Instant::now() - Duration::from_secs(61);
        server.clients.insert(2, client);
        server.tick();
        assert_eq!(rx.try_recv().unwrap(), "ERROR :Connection timed out\r\n");
        assert!(server.clients.is_empty());
    }

    #[test]
    fn protocol_boundaries() {
        let msg = parse("@ignored=yes :spoof PRIVmsg #test :hello world").unwrap();
        assert_eq!(msg.command, "PRIVMSG");
        assert_eq!(msg.params, ["#test", "hello world"]);
        assert_eq!(parse("TOPIC #test :").unwrap().params, ["#test", ""]);
        assert!(parse("PRIVMSG #test :bad\0text").is_none());
        assert_eq!(fold("[Nick]\\^"), fold("{NICK}|~"));
        assert!(nick_valid("Guest-1"));
        assert!(!nick_valid("1guest"));
        assert!(!channel_valid("#bad,name"));
        assert_eq!(truncate("éé", 3), "é");
        assert_eq!(shown_host("::1"), "0::1");
        assert_eq!(shown_host("::ffff:192.0.2.1"), "0::ffff:192.0.2.1");
        assert_eq!(shown_host("2001:db8::1"), "2001:db8::1");
        assert_eq!(shown_host("127.0.0.1"), "127.0.0.1");
        assert_eq!(utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(utc(951_782_400), "2000-02-29 00:00:00 UTC");
        assert_eq!(utc(1_794_268_799), "2026-11-09 23:59:59 UTC");
    }
}
