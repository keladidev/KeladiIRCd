//! Services link: the ngIRCd server protocol (RFC 2813 with ngIRCd's extensions),
//! so services such as Anope can link with their `ngircd` protocol module.
//!
//! Outgoing YamIRCd frames are translated by `View`, which remembers what services
//! have been told so state changes go out as differences. Incoming commands run as
//! privileged actions of a service bot, or of the services server's hidden stand-in.
use super::*;
use network::{decode, encode};
use std::{io::BufReader, net::IpAddr};

#[derive(Clone)]
pub struct ServicesConfig {
    pub name: String,
    pub incoming_ip: IpAddr,
    pub password: String,
}

pub(crate) fn validate_config(config: &Config) -> io::Result<()> {
    let invalid = |why: &str| Err(io::Error::new(io::ErrorKind::InvalidInput, why.to_string()));
    let mut names = BTreeSet::new();
    for s in &config.services {
        if !network::server_name_valid(&s.name)
            || fold(&s.name) == fold(&config.name)
            || config.links.iter().any(|l| fold(&l.name) == fold(&s.name))
            || !names.insert(fold(&s.name))
            || s.password.is_empty()
            || s.password.len() > 128
            || s.password.contains([' ', '\0', '\r', '\n'])
        {
            return invalid("Invalid or duplicate services configuration");
        }
    }
    if !config.services.is_empty() && config.link_listen.is_none() {
        return invalid("Configured services require --link-listen");
    }
    Ok(())
}

/// Services account names: 1-64 printable bytes without spaces or commas.
pub(crate) fn account_valid(account: &str) -> bool {
    !account.is_empty()
        && account.len() <= 64
        && account.bytes().all(|b| b > b' ' && b != 127 && b != b',')
}

/// User hosts: an IP address, or a hostname such as `services.host` for service bots.
pub(crate) fn host_valid(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok()
        || (!host.is_empty()
            && host.len() <= 63
            && !host.starts_with(':')
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-:/".contains(&b)))
}

/// Splits an optional `:source` prefix from a server-protocol line.
fn split_source(line: &str) -> (Option<&str>, &str) {
    let line = line.trim_start_matches(' ');
    match line.strip_prefix(':') {
        Some(rest) => rest
            .split_once(' ')
            .map_or((Some(rest), ""), |(source, rest)| (Some(source), rest)),
        None => (None, line),
    }
}

/// A user as services know it.
struct Seen {
    nick: String,
    home: String,
    /// Letters from `ioR`.
    modes: String,
    account: String,
}

/// A channel as services know it; it exists for them while it has members.
#[derive(Default)]
struct SeenChannel {
    name: String,
    flags: String,
    key: String,
    limit: usize,
    bans: Vec<String>,
    topic: String,
    members: BTreeMap<String, u8>,
}

pub(crate) struct View {
    /// The services server's name.
    name: String,
    /// The hidden client that stands in for the services server itself.
    pub(crate) actor: u64,
    /// While services' own commands run, their effects update the view silently.
    pub(crate) quiet: bool,
    /// Other YamIRCd servers and the tokens they were introduced with.
    servers: BTreeMap<String, u32>,
    next_token: u32,
    users: BTreeMap<String, Seen>,
    channels: BTreeMap<String, SeenChannel>,
}

/// Mode lines of at most ten changes each.
fn mode_lines(me: &str, target: &str, changes: &[(bool, char, Option<String>)]) -> Vec<String> {
    changes
        .chunks(10)
        .map(|chunk| {
            let mut modes = String::new();
            let mut args = String::new();
            for (adding, mode, arg) in chunk {
                channel::push_mode(&mut modes, *adding, *mode);
                if let Some(arg) = arg {
                    args.push(' ');
                    args.push_str(arg);
                }
            }
            format!(":{me} MODE {target} {modes}{args}")
        })
        .collect()
}

fn status_changes(old: u8, new: u8, nick: &str) -> Vec<(bool, char, Option<String>)> {
    [(channel::OP, 'o'), (channel::VOICE, 'v')]
        .iter()
        .filter(|(bit, _)| old & bit != new & bit)
        .map(|(bit, mode)| (new & bit != 0, *mode, Some(nick.to_string())))
        .collect()
}

impl View {
    pub(crate) fn new(name: String, actor: u64) -> Self {
        Self {
            name,
            actor,
            quiet: false,
            servers: BTreeMap::new(),
            // Token 1 is this server, which services know as their uplink.
            next_token: 2,
            users: BTreeMap::new(),
            channels: BTreeMap::new(),
        }
    }

    /// Records the expected result of a change services made to a user on another
    /// YamIRCd server, so the update coming back from there is not echoed to them.
    fn assume(&mut self, uid: &str, msg: &Message) {
        let Some(seen) = self.users.get_mut(uid) else {
            return;
        };
        let param = msg.params.first().map(String::as_str).unwrap_or("");
        match msg.command.as_str() {
            "ACCOUNT" => seen.account = param.into(),
            "UMODE" => {
                seen.modes.retain(|c| c != 'R');
                if param == "+R" {
                    seen.modes.push('R');
                }
            }
            _ => {}
        }
    }

    pub(crate) fn translate(&mut self, server: &Server, frame: &str) -> Vec<String> {
        let lines = self.translate_frame(server, frame).unwrap_or_default();
        if self.quiet {
            Vec::new()
        } else {
            lines
        }
    }

    fn forget_user(&mut self, uid: &str) -> Option<Seen> {
        self.channels.retain(|_, ch| {
            ch.members.remove(uid);
            !ch.members.is_empty()
        });
        self.users.remove(uid)
    }

    fn chaninfo(&self, me: &str, ch: &SeenChannel) -> Vec<String> {
        let mut modes = format!("+{}", ch.flags);
        let line = if ch.key.is_empty() && ch.limit == 0 {
            format!(":{me} CHANINFO {} {modes} :{}", ch.name, ch.topic)
        } else {
            if !ch.key.is_empty() {
                modes.push('k');
            }
            if ch.limit > 0 {
                modes.push('l');
            }
            let key = if ch.key.is_empty() { "*" } else { &ch.key };
            format!(
                ":{me} CHANINFO {} {modes} {key} {} :{}",
                ch.name, ch.limit, ch.topic
            )
        };
        let bans: Vec<_> = ch
            .bans
            .iter()
            .map(|ban| (true, 'b', Some(ban.clone())))
            .collect();
        let mut lines = vec![line];
        lines.extend(mode_lines(me, &ch.name, &bans));
        lines
    }

    /// The nickname services know for the user `uid`, or this server's name.
    fn source<'a>(&'a self, uid: &str, me: &'a str) -> &'a str {
        self.users.get(uid).map_or(me, |u| u.nick.as_str())
    }

    /// The service bot that relays a channel's messages to services, so a message
    /// reaching several bots in one channel is passed on once.
    fn relay_bot(&self, key: &str) -> Option<&str> {
        let ch = self.channels.get(key)?;
        ch.members
            .keys()
            .filter(|uid| self.users.get(*uid).is_some_and(|u| u.home == self.name))
            .min()
            .map(String::as_str)
    }

    fn translate_frame(&mut self, server: &Server, frame: &str) -> Option<Vec<String>> {
        let p: Vec<_> = frame.split(' ').collect();
        let me = server.config.name.as_str();
        let mut out = Vec::new();
        match (p[0], p.len()) {
            ("SERVER", 2) => {
                let name = p[1];
                if name != me && name != self.name && !self.servers.contains_key(name) {
                    let token = self.next_token;
                    self.next_token += 1;
                    self.servers.insert(name.into(), token);
                    out.push(format!(":{me} SERVER {name} 2 {token} :YamIRC server"));
                }
            }
            ("USER", 11) => {
                let uid = p[1];
                let home = uid.split('!').next()?.to_string();
                let (nick, user, host, real) =
                    (decode(p[2])?, decode(p[3])?, decode(p[4])?, decode(p[5])?);
                // The frame carries operator status as a class and the other modes as i/R.
                let umodes = decode(p[8])?;
                let modes: String = "ioR"
                    .chars()
                    .filter(|&c| {
                        if c == 'o' {
                            p[7] != "-"
                        } else {
                            umodes.contains(c)
                        }
                    })
                    .collect();
                let account = decode(p[9])?;
                if home == self.name {
                    // Service bots: services already know them.
                    self.users.insert(
                        uid.into(),
                        Seen {
                            nick,
                            home,
                            modes,
                            account,
                        },
                    );
                } else if let Some(seen) = self.users.get_mut(uid) {
                    if seen.nick != nick {
                        out.push(format!(":{} NICK :{nick}", seen.nick));
                        seen.nick = nick;
                    }
                    let mut diff = String::new();
                    for c in "ioR".chars() {
                        if seen.modes.contains(c) != modes.contains(c) {
                            channel::push_mode(&mut diff, modes.contains(c), c);
                        }
                    }
                    if !diff.is_empty() {
                        out.push(format!(":{me} MODE {} :{diff}", seen.nick));
                        seen.modes = modes;
                    }
                    if seen.account != account {
                        out.push(format!(
                            ":{me} METADATA {} accountname :{account}",
                            seen.nick
                        ));
                        seen.account = account;
                    }
                } else {
                    let token = if home == me {
                        1
                    } else {
                        *self.servers.get(&home)?
                    };
                    out.push(format!(
                        ":{me} NICK {nick} 1 {user} {} {token} +{modes} :{real}",
                        shown_host(&host)
                    ));
                    if !account.is_empty() {
                        out.push(format!(":{me} METADATA {nick} accountname :{account}"));
                    }
                    self.users.insert(
                        uid.into(),
                        Seen {
                            nick,
                            home,
                            modes,
                            account,
                        },
                    );
                }
            }
            ("REMOVE", 3) | ("COLLIDE", 2) => {
                let reason = if p[0] == "REMOVE" {
                    decode(p[2])?
                } else {
                    "Nickname collision".into()
                };
                if let Some(seen) = self.forget_user(p[1]) {
                    if seen.home == self.name {
                        // A bot killed by a user: services reintroduce it.
                        out.push(format!(":{me} KILL {} :{reason}", seen.nick));
                    } else {
                        out.push(format!(":{} QUIT :{reason}", seen.nick));
                    }
                }
            }
            ("SPLIT", 3) => {
                let (names, reason) = (decode(p[1])?, decode(p[2])?);
                let names: Vec<_> = names.split(',').collect();
                for name in &names {
                    if self.servers.remove(*name).is_some() {
                        out.push(format!(":{me} SQUIT {name} :{reason}"));
                    }
                }
                // Services drop the users of a server that quits.
                let gone: Vec<_> = self
                    .users
                    .iter()
                    .filter(|(_, u)| names.contains(&u.home.as_str()))
                    .map(|(uid, _)| uid.clone())
                    .collect();
                for uid in gone {
                    self.forget_user(&uid);
                }
            }
            ("CHAN", 13) => {
                let by = self.source(p[12], me).to_string();
                let name = decode(p[1])?;
                let bans = decode(p[11])?;
                let new = SeenChannel {
                    name,
                    flags: decode(p[4])?,
                    key: decode(p[5])?,
                    limit: p[6].parse().ok()?,
                    topic: decode(p[7])?,
                    bans: bans
                        .split(',')
                        .filter(|b| !b.is_empty())
                        .map(String::from)
                        .collect(),
                    members: BTreeMap::new(),
                };
                let topic_by = decode(p[8])?;
                let setter = topic_by.split('!').next().unwrap_or(me);
                let setter = if self.users.values().any(|u| u.nick == setter) {
                    setter
                } else {
                    me
                };
                let key = fold(&new.name);
                let old = self.channels.entry(key).or_insert_with(|| SeenChannel {
                    name: new.name.clone(),
                    ..Default::default()
                });
                if !old.members.is_empty() {
                    let mut changes = Vec::new();
                    for c in "imnrst".chars() {
                        if old.flags.contains(c) != new.flags.contains(c) {
                            changes.push((new.flags.contains(c), c, None));
                        }
                    }
                    if old.key != new.key {
                        changes.push(if new.key.is_empty() {
                            (false, 'k', Some("*".into()))
                        } else {
                            (true, 'k', Some(new.key.clone()))
                        });
                    }
                    if old.limit != new.limit {
                        changes.push(if new.limit == 0 {
                            (false, 'l', None)
                        } else {
                            (true, 'l', Some(new.limit.to_string()))
                        });
                    }
                    for ban in old.bans.iter().filter(|b| !new.bans.contains(b)) {
                        changes.push((false, 'b', Some(ban.clone())));
                    }
                    for ban in new.bans.iter().filter(|b| !old.bans.contains(b)) {
                        changes.push((true, 'b', Some(ban.clone())));
                    }
                    out.extend(mode_lines(&by, &old.name, &changes));
                    if old.topic != new.topic {
                        out.push(format!(":{setter} TOPIC {} :{}", old.name, new.topic));
                    }
                }
                (old.flags, old.key, old.limit, old.bans, old.topic) =
                    (new.flags, new.key, new.limit, new.bans, new.topic);
            }
            ("MEMBER", 8) => {
                let name = decode(p[1])?;
                let key = fold(&name);
                let uid = p[2];
                let by = self.source(p[6], me).to_string();
                let seen = self.users.get(uid)?;
                let (nick, bot) = (seen.nick.clone(), seen.home == self.name);
                let ch = self
                    .channels
                    .entry(key.clone())
                    .or_insert_with(|| SeenChannel {
                        name,
                        ..Default::default()
                    });
                if p[3] == "-" {
                    if ch.members.remove(uid).is_some() {
                        // A bot leaves only when removed by someone else, so report a kick.
                        out.push(if p[7] != "-" {
                            format!(":{by} KICK {} {nick} :{}", ch.name, decode(p[7])?)
                        } else if bot {
                            format!(":{me} KICK {} {nick} :Removed from channel", ch.name)
                        } else {
                            format!(":{nick} PART {}", ch.name)
                        });
                    }
                    if ch.members.is_empty() {
                        self.channels.remove(&key);
                    }
                } else {
                    let status: u8 = p[3].parse().ok()?;
                    match ch.members.insert(uid.into(), status) {
                        None => {
                            out.push(format!(":{nick} JOIN {}", ch.name));
                            if ch.members.len() == 1 {
                                let ch = &self.channels[&key];
                                out.extend(self.chaninfo(me, ch));
                            }
                            let ch = &self.channels[&key];
                            // Status given on joining (op for a channel's creator) is the server's.
                            out.extend(mode_lines(me, &ch.name, &status_changes(0, status, &nick)));
                        }
                        Some(old) if old != status => {
                            out.extend(mode_lines(
                                &by,
                                &ch.name,
                                &status_changes(old, status, &nick),
                            ));
                        }
                        Some(_) => {}
                    }
                }
            }
            ("WIRE", 3) => {
                // Only messages reach services this way; state arrives as frames above.
                let text = decode(p[2])?;
                let (prefix, rest) = text.strip_prefix(':')?.split_once(' ')?;
                let (command, args) = rest.split_once(' ')?;
                let target = args.split(' ').next()?;
                let relayed = matches!(command, "PRIVMSG" | "NOTICE")
                    && (!target.starts_with(['#', '&'])
                        || self.relay_bot(&fold(target)) == Some(p[1]));
                if relayed {
                    out.push(format!(":{} {rest}", prefix.split('!').next()?));
                }
            }
            _ => {}
        }
        Some(out)
    }
}

/// Runs a services link that started with `first` (its PASS line).
pub(super) fn session(
    socket: TcpStream,
    mut reader: BufReader<TcpStream>,
    state: Arc<Mutex<Server>>,
    first: String,
    remote_ip: IpAddr,
) -> io::Result<()> {
    let denied = |why: &str| io::Error::new(io::ErrorKind::PermissionDenied, why.to_string());
    let pass = parse(split_source(&first).1)
        .filter(|m| m.command == "PASS" && !m.params.is_empty())
        .ok_or_else(|| denied("Expected PASS"))?;
    let second = network::read_line(&mut reader)?;
    let hello = parse(split_source(&second).1)
        .filter(|m| m.command == "SERVER" && m.params.len() >= 2)
        .ok_or_else(|| denied("Expected SERVER"))?;
    let (tx, rx) = mpsc::sync_channel(network::LINK_QUEUE);
    let (id, name) = {
        let mut state = state.lock().unwrap();
        let config = state
            .config
            .services
            .iter()
            .find(|s| {
                s.name == hello.params[0]
                    && s.incoming_ip == remote_ip
                    && s.password == pass.params[0]
            })
            .cloned()
            .ok_or_else(|| denied("Unknown services server, IP or password"))?;
        if state.links.len() >= 8 || state.routes.keys().any(|k| fold(k) == fold(&config.name)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Services server already linked",
            ));
        }
        state.next_id += 2;
        let (id, actor) = (state.next_id - 1, state.next_id);
        let view = View::new(config.name.clone(), actor);
        let link = network::Link::new(config.name.clone(), tx, socket.try_clone()?, Some(view));
        let (actor_tx, actor_socket) =
            link.handles().ok_or_else(|| denied("Socket unavailable"))?;
        state.links.insert(id, link);
        state.routes.insert(config.name.clone(), id);
        state.net_flood(Some(id), &format!("SERVER {}", config.name));
        // The services server's own commands run as this hidden, unregistered client.
        let uid = format!("{}!0!0", config.name);
        let mut c = Client::new(
            uid,
            config.name.clone(),
            config.name.clone(),
            actor_tx,
            actor_socket,
        );
        (c.route, c.server) = (Some(id), true);
        state.clients.insert(actor, c);
        let me = state.config.name.clone();
        let link = &state.links[&id];
        link.raw(&format!(
            "PASS {} 0210-IRC+ YamIRCd|0.1.0:CM P",
            config.password
        ));
        link.raw(&format!("SERVER {me} 1 :{}", state.config.description));
        link.raw(&format!(
            ":{me} 005 {} NICKLEN=30 CASEMAPPING=rfc1459 :are supported by this server",
            config.name
        ));
        state.burst(id);
        (id, config.name)
    };
    eprintln!("Services {name} connected");
    network::spawn_writer(Arc::clone(&state), id, socket.try_clone()?, rx);
    // A quiet link gets a PING on read timeout; any line proves it is alive.
    let mut waiting = false;
    let result = loop {
        match network::read_line(&mut reader) {
            Ok(line) => {
                waiting = false;
                let mut server = state.lock().unwrap();
                if !server.links.contains_key(&id) || !server.services_line(id, &line) {
                    break Ok(());
                }
            }
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) && !waiting =>
            {
                let server = state.lock().unwrap();
                let me = &server.config.name;
                if let Some(link) = server.links.get(&id) {
                    link.raw(&format!(":{me} PING :{me}"));
                }
                waiting = true;
            }
            Err(err) => break Err(err),
        }
    };
    state.lock().unwrap().drop_link(id, "Services link lost");
    result
}

impl Server {
    fn set_quiet(&self, link: u64, quiet: bool) {
        if let Some(mut view) = self.links.get(&link).and_then(network::Link::view) {
            view.quiet = quiet;
        }
    }

    /// A registered network user services may act on (not one of their own).
    fn user_for_services(&self, nick: &str) -> Option<u64> {
        self.find_nick(nick)
            .filter(|id| self.clients[id].registered && !self.is_service(*id))
    }

    /// Handles one line from services; false closes the link.
    fn services_line(&mut self, link: u64, line: &str) -> bool {
        let (source, rest) = split_source(line);
        // Numerics (such as 376 ending the handshake) fail to parse and are ignored.
        let Some(msg) = parse(rest) else {
            return true;
        };
        let services = self.links[&link].name.clone();
        let Some(server_actor) = self.links[&link].view().map(|v| v.actor) else {
            return false;
        };
        let actor = match source {
            Some(s) if !s.eq_ignore_ascii_case(&services) => {
                match self
                    .find_nick(s)
                    .filter(|id| self.clients[id].route == Some(link))
                {
                    Some(id) => id,
                    None => return true,
                }
            }
            _ => server_actor,
        };
        let me = self.config.name.clone();
        match msg.command.as_str() {
            "PING" => {
                let token = msg.params.first().map_or(services.as_str(), String::as_str);
                self.links[&link].raw(&format!(":{me} PONG {me} :{token}"));
                return true;
            }
            "ERROR" => return false,
            "SQUIT" => {
                return !msg.params.first().is_some_and(|s| {
                    s.eq_ignore_ascii_case(&services) || s.eq_ignore_ascii_case(&me)
                })
            }
            _ => {}
        }
        // Services' own changes are not echoed back to them, except forced nickname
        // changes, which they expect to hear about.
        self.set_quiet(link, msg.command != "SVSNICK");
        let before = self.channels.clone();
        self.services_command(link, actor, &msg);
        self.sync_channels(&before, Some(actor));
        self.set_quiet(link, false);
        true
    }

    fn services_command(&mut self, link: u64, actor: u64, msg: &Message) {
        let p = &msg.params;
        let text = |i: usize| p.get(i).map_or("", String::as_str);
        let is_server = self.clients[&actor].server;
        match (msg.command.as_str(), is_server) {
            ("NICK", true) if p.len() >= 7 => {
                self.introduce_service(link, &p[0], &p[2], &p[3], &p[5], &p[6]);
            }
            ("NICK", false) if !p.is_empty() => {
                if nick_valid(&p[0]) && p[0] != self.clients[&actor].nick {
                    self.free_nick_for_services(link, &p[0]);
                    self.change_nick(actor, &p[0]);
                    self.net_flood(None, &self.user_record(actor));
                }
            }
            ("JOIN", false) if !p.is_empty() => {
                for name in p[0].split(',') {
                    // RFC 2813 may append "\x07modes" to a channel name.
                    let name = name.split('\x07').next().unwrap_or_default();
                    self.join_channel(actor, name, None, true);
                }
            }
            ("PART", false) if !p.is_empty() => {
                for name in p[0].split(',') {
                    self.part(actor, name, text(1));
                }
            }
            ("QUIT", false) => {
                let uid = self.clients[&actor].uid.clone();
                self.remember_deleted(&uid);
                self.disconnect(actor, text(0));
                self.net_flood(None, &format!("REMOVE {uid} {}", encode(text(0))));
            }
            ("MODE", _) if p.len() >= 2 => {
                if p[0].starts_with(['#', '&']) {
                    if self.channels.contains_key(&fold(&p[0])) {
                        self.channel_mode(actor, p);
                    }
                } else if let Some(target) = self.user_for_services(&p[0]) {
                    // Only +R (identified) is set by services; other user modes are ignored.
                    let mut adding = true;
                    for mode in p[1].chars() {
                        match mode {
                            '+' => adding = true,
                            '-' => adding = false,
                            'R' => {
                                let mode = if adding { "+R" } else { "-R" };
                                self.services_force(link, target, &format!("UMODE {mode}"));
                            }
                            _ => {}
                        }
                    }
                }
            }
            ("KICK", _) if p.len() >= 2 => self.kick(actor, p),
            ("KILL", _) if !p.is_empty() => {
                if let Some(target) = self.user_for_services(&p[0]) {
                    self.kill_user(actor, target, text(1));
                }
            }
            ("TOPIC", _) if p.len() >= 2 => {
                let key = fold(&p[0]);
                if self.channels.contains_key(&key) {
                    self.set_topic(actor, &key, &p[1]);
                }
            }
            ("INVITE", _) if p.len() >= 2 => self.invite(actor, p),
            ("PRIVMSG" | "NOTICE", _) if p.len() >= 2 => {
                if let Some(mask) = p[0].strip_prefix('$') {
                    // Global messages go to every user on servers matching the mask.
                    let mask = fold(mask);
                    let line = format!(
                        ":{} {} {} :{}",
                        self.clients[&actor].prefix(),
                        msg.command,
                        p[0],
                        p[1]
                    );
                    let targets: Vec<_> = self
                        .clients
                        .iter()
                        .filter(|(id, c)| {
                            c.registered
                                && !self.is_service(**id)
                                && oper::matches(&mask, &fold(&c.home))
                        })
                        .map(|(&id, _)| id)
                        .collect();
                    self.broadcast(targets, &line);
                } else {
                    self.message(actor, &msg.command, p);
                }
            }
            ("SVSNICK", true) if p.len() >= 2 => {
                if let Some(target) = self.user_for_services(&p[0]) {
                    if nick_valid(&p[1]) && self.find_nick(&p[1]).is_none_or(|o| o == target) {
                        self.services_force(link, target, &format!("NICK {}", p[1]));
                    }
                }
            }
            // Anope's names: `cloakhost` is the displayed host, `user` the username.
            ("METADATA", true) if p.len() >= 3 && p[1] == "cloakhost" => {
                if let Some(target) = self.user_for_services(&p[0]) {
                    if p[2].is_empty() || host_valid(&p[2]) {
                        self.services_force(link, target, &format!("VHOST {}", p[2]));
                    }
                }
            }
            ("METADATA", true) if p.len() >= 3 && p[1] == "user" => {
                if let Some(target) = self.user_for_services(&p[0]) {
                    if username_valid(&p[2]) && p[2] != self.clients[&target].user {
                        self.services_force(link, target, &format!("VIDENT {}", p[2]));
                    }
                }
            }
            ("METADATA", true) if p.len() >= 2 && p[1] == "accountname" => {
                if let Some(target) = self.user_for_services(&p[0]) {
                    let account = text(2);
                    if account.is_empty() {
                        self.services_force(link, target, "ACCOUNT");
                    } else if account_valid(account) {
                        self.services_force(link, target, &format!("ACCOUNT {account}"));
                    }
                }
            }
            ("WALLOPS", _) if !p.is_empty() => {
                let line = format!(":{} WALLOPS :{}", self.clients[&actor].prefix(), p[0]);
                let opers: Vec<_> = self
                    .clients
                    .iter()
                    .filter(|(id, c)| c.registered && c.oper.is_some() && !self.is_service(**id))
                    .map(|(&id, _)| id)
                    .collect();
                self.broadcast(opers, &line);
            }
            ("CHANINFO", true) if p.len() >= 2 => {
                let key = fold(&p[0]);
                if !self.channels.contains_key(&key) {
                    return;
                }
                let mut args = vec![p[0].clone(), p[1].clone()];
                if p.len() >= 5 {
                    if p[1].contains('k') {
                        args.push(p[2].clone());
                    }
                    if p[1].contains('l') {
                        args.push(p[3].clone());
                    }
                }
                self.channel_mode(actor, &args);
                let topic = match p.len() {
                    3 => Some(&p[2]),
                    5.. => Some(&p[4]),
                    _ => None,
                };
                if let Some(topic) = topic.filter(|t| **t != self.channels[&key].topic) {
                    self.set_topic(actor, &key, topic);
                }
            }
            ("GLINE", true) if !p.is_empty() => {
                // AKILL: GLINE <mask> <seconds> :<reason> adds, GLINE <mask> removes.
                let Some(mask) = bans::ban_mask(&p[0]) else {
                    return;
                };
                if p.len() >= 3 {
                    let seconds = p[1].parse().unwrap_or(0);
                    let setter = self.links[&link].name.clone();
                    if self.add_server_ban(mask, seconds, &p[2], &setter, true) {
                        let ban = self.server_bans.last().unwrap();
                        self.net_flood(None, &self.gline_record(ban));
                    }
                } else if self.remove_server_ban(&mask, true) {
                    self.net_flood(None, &format!("UNGLINE {}", encode(&mask)));
                }
            }
            // Jupes, STATS and the like are not supported.
            _ => {}
        }
    }

    fn introduce_service(
        &mut self,
        link: u64,
        nick: &str,
        user: &str,
        host: &str,
        modes: &str,
        real: &str,
    ) {
        if !nick_valid(nick) || !username_valid(user) || !host_valid(host) {
            eprintln!("Ignoring invalid services user {nick}");
            return;
        }
        if self.find_nick(nick).is_some_and(|id| self.is_service(id)) {
            return;
        }
        self.free_nick_for_services(link, nick);
        let Some((tx, socket)) = self.links[&link].handles() else {
            return;
        };
        self.next_id += 1;
        let id = self.next_id;
        let services = self.links[&link].name.clone();
        let uid = format!("{services}!{}!{id}", self.boot);
        let mut c = Client::new(uid, services, host.into(), tx, socket);
        c.route = Some(link);
        (c.nick, c.user, c.real) = (nick.into(), user.into(), truncate(real, 128).into());
        c.registered = true;
        c.oper = modes.contains('o').then_some(OperClass::Override);
        c.invisible = modes.contains('i');
        self.clients.insert(id, c);
        self.note_peak();
        self.net_flood(None, &self.user_record(id));
    }

    /// Services take precedence: a user holding a nickname they introduce is killed.
    fn free_nick_for_services(&mut self, link: u64, nick: &str) {
        let Some(other) = self.find_nick(nick).filter(|id| !self.is_service(*id)) else {
            return;
        };
        let Some(actor) = self.links[&link].view().map(|v| v.actor) else {
            return;
        };
        let (registered, held) = (
            self.clients[&other].registered,
            self.clients[&other].nick.clone(),
        );
        self.kill_user(actor, other, "Nickname collision with services");
        // This runs quietly, so tell services explicitly that the user is gone.
        if registered {
            self.links[&link].raw(&format!(":{held} QUIT :Nickname collision with services"));
        }
    }

    /// Applies a services action to a user, forwarding it to the user's home server
    /// when the user is on another YamIRCd server.
    fn services_force(&mut self, link: u64, target: u64, command: &str) {
        let services = self.links[&link].name.clone();
        let Some(msg) = parse(command) else {
            return;
        };
        if let Some(route) = self.clients[&target].route {
            let uid = self.clients[&target].uid.clone();
            self.link_send(
                route,
                &format!("FORCE {services} {uid} {}", encode(command)),
            );
            // Forced nickname changes come back as news services expect; others do not.
            if let Some(mut view) = self.links[&link].view() {
                view.assume(&uid, &msg);
            }
        } else {
            let before = self.user_record(target);
            self.force(target, &msg, &services);
            let after = self.user_record(target);
            if after != before {
                self.net_flood(None, &after);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_helpers() {
        assert_eq!(
            split_source(":NickServ NOTICE x :hi"),
            (Some("NickServ"), "NOTICE x :hi")
        );
        assert_eq!(split_source("PING :a"), (None, "PING :a"));
        assert!(host_valid("services.host") && host_valid("::1") && host_valid("127.0.0.1"));
        assert!(!host_valid("bad host") && !host_valid(":x") && !host_valid(""));
        assert!(account_valid("Alice") && !account_valid("a b") && !account_valid(""));
        let changes = [
            (true, 'o', Some("a".into())),
            (false, 'v', Some("b".into())),
        ];
        assert_eq!(mode_lines("me", "#c", &changes), [":me MODE #c +o-v a b"]);
        assert_eq!(status_changes(channel::OP, channel::VOICE, "n").len(), 2);
    }
}
