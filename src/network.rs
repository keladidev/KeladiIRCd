//! YamIRCd link protocol v2: authenticated tree links, replicated state, routed delivery.
//! This is deliberately not an UnrealIRCd wire protocol implementation.
use super::*;
use std::{
    cell::RefCell,
    io::{BufRead, BufReader},
    net::SocketAddr,
};

const LINK_LINE: usize = 8192;
pub(super) const LINK_QUEUE: usize = 16384;
/// Peers must speak the same version; v2 added channel modes, voice and invisibility.
const PROTOCOL_VERSION: &str = "2";

#[derive(Clone)]
pub struct LinkConfig {
    pub name: String,
    pub address: Option<SocketAddr>,
    pub incoming_ip: std::net::IpAddr,
    pub password: String,
}

pub(super) struct Link {
    pub name: String,
    tx: SyncSender<String>,
    socket: TcpStream,
    /// Set for a services link: what services have been told, for translation.
    services: Option<RefCell<services::View>>,
}

impl Link {
    pub(super) fn new(
        name: String,
        tx: SyncSender<String>,
        socket: TcpStream,
        services: Option<services::View>,
    ) -> Self {
        Self {
            name,
            tx,
            socket,
            services: services.map(RefCell::new),
        }
    }

    /// Handles for a remote user routed over this link.
    pub(super) fn handles(&self) -> Option<(SyncSender<String>, TcpStream)> {
        Some((self.tx.clone(), self.socket.try_clone().ok()?))
    }

    pub(super) fn is_services(&self) -> bool {
        self.services.is_some()
    }

    pub(super) fn view(&self) -> Option<std::cell::RefMut<'_, services::View>> {
        self.services.as_ref().map(RefCell::borrow_mut)
    }

    /// Queues a line as is; a full queue or overlong line closes the link.
    pub(super) fn raw(&self, line: &str) {
        if line.len() > LINK_LINE || self.tx.try_send(format!("{line}\r\n")).is_err() {
            let _ = self.socket.shutdown(Shutdown::Both);
        }
    }
}

pub(super) fn millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub(super) fn encode(value: &str) -> String {
    if value.is_empty() {
        return "-".into();
    }
    value.bytes().map(|b| format!("{b:02x}")).collect()
}

pub(super) fn decode(value: &str) -> Option<String> {
    if value == "-" {
        return Some(String::new());
    }
    if value.len() % 2 != 0 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let bytes: Option<Vec<_>> = (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).ok())
        .collect();
    let text = String::from_utf8(bytes?).ok()?;
    if text.contains(['\0', '\r', '\n']) {
        return None;
    }
    Some(text)
}

/// Revision 0 so any real CHAN record for this channel replaces these defaults.
fn placeholder_channel(name: &str) -> Channel {
    Channel::new(name, 0, 0, String::new())
}

/// Server names in link frames: 1-63 ASCII letters, digits, dots or hyphens.
pub(super) fn server_name_valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
}

pub(super) fn validate_config(config: &Config) -> io::Result<()> {
    let mut names = BTreeSet::new();
    if config.links.len() > 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "At most eight links may be configured",
        ));
    }
    for link in &config.links {
        if link.name.is_empty()
            || link.name.len() > 63
            || !link
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
            || fold(&link.name) == fold(&config.name)
            || link.password.is_empty()
            || link.password.len() > 128
            || link.password.contains(['\0', '\r', '\n'])
            || !names.insert(fold(&link.name))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid or duplicate link configuration",
            ));
        }
    }
    if !config.links.is_empty() && config.link_listen.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Configured links require --link-listen",
        ));
    }
    Ok(())
}

impl Server {
    /// Sends a YamIRCd frame; a services link receives it translated to its protocol.
    pub(super) fn link_send(&self, id: u64, line: &str) {
        let Some(link) = self.links.get(&id) else {
            return;
        };
        if let Some(mut view) = link.view() {
            for line in view.translate(self, line) {
                link.raw(&line);
            }
        } else {
            link.raw(line);
        }
    }

    pub(super) fn net_flood(&self, except: Option<u64>, line: &str) {
        for &id in self.links.keys() {
            if Some(id) != except {
                self.link_send(id, line);
            }
        }
    }

    fn uid_id(&self, uid: &str) -> Option<u64> {
        self.clients
            .iter()
            .find(|(_, c)| c.uid == uid)
            .map(|(&id, _)| id)
    }

    pub(super) fn user_record(&self, id: u64) -> String {
        let c = &self.clients[&id];
        format!(
            "USER {} {} {} {} {} {} {} {} {}",
            c.uid,
            encode(&c.nick),
            encode(&c.user),
            encode(&c.host),
            encode(&c.real),
            encode(&c.away),
            c.oper.map(OperClass::name).unwrap_or("-"),
            // Operator status travels as the class above; the modes field holds i and R.
            encode(&c.modes().replace('o', "")),
            encode(&c.account)
        )
    }

    pub(super) fn remember_deleted(&mut self, uid: &str) {
        if self.deleted_users.len() >= 8192 {
            if let Some(oldest) = self
                .deleted_users
                .iter()
                .min_by_key(|(_, at)| **at)
                .map(|(uid, _)| uid.clone())
            {
                self.deleted_users.remove(&oldest);
            }
        }
        self.deleted_users.insert(uid.into(), Instant::now());
    }

    fn channel_record(&self, ch: &Channel) -> String {
        format!(
            "CHAN {} {} {} {} {} {} {} {} {} {} {}",
            encode(&ch.name),
            ch.revision,
            ch.revision_by,
            encode(&ch.flags()),
            encode(&ch.key),
            ch.limit,
            encode(&ch.topic),
            encode(&ch.topic_by),
            ch.topic_at,
            ch.created,
            encode(&ch.bans.join(","))
        )
    }

    pub(super) fn sync_channels(&mut self, before: &BTreeMap<String, Channel>) {
        let keys: Vec<_> = self
            .channels
            .keys()
            .filter(|k| k.starts_with('#'))
            .cloned()
            .collect();
        for key in keys {
            let old = before.get(&key);
            let ch = &self.channels[&key];
            let changed = old.is_none_or(|old| !old.same_meta(ch));
            if changed {
                let ch = self.channels.get_mut(&key).unwrap();
                ch.revision = millis().max(ch.revision.saturating_add(1));
                ch.revision_by = self.config.name.clone();
                self.net_flood(None, &self.channel_record(&self.channels[&key]));
            }
            let ch = &self.channels[&key];
            for (&id, &status) in &ch.members {
                if old.is_none_or(|old| old.members.get(&id) != Some(&status)) {
                    let uid = &self.clients[&id].uid;
                    let version = self
                        .member_versions
                        .entry((key.clone(), uid.clone()))
                        .or_default();
                    *version = (
                        millis().max(version.0.saturating_add(1)),
                        self.config.name.clone(),
                    );
                    let record = format!(
                        "MEMBER {} {uid} {status} {} {}",
                        encode(&ch.name),
                        version.0,
                        version.1
                    );
                    self.net_flood(None, &record);
                }
            }
        }
        for (key, old) in before.iter().filter(|(key, _)| key.starts_with('#')) {
            for &id in old.members.keys() {
                if self
                    .channels
                    .get(key)
                    .is_none_or(|ch| !ch.members.contains_key(&id))
                {
                    if let Some(c) = self.clients.get(&id) {
                        let version = self
                            .member_versions
                            .entry((key.clone(), c.uid.clone()))
                            .or_default();
                        *version = (
                            millis().max(version.0.saturating_add(1)),
                            self.config.name.clone(),
                        );
                        let record = format!(
                            "MEMBER {} {} - {} {}",
                            encode(&old.name),
                            c.uid,
                            version.0,
                            version.1
                        );
                        self.net_flood(None, &record);
                    }
                }
            }
        }
    }

    pub(super) fn burst(&self, link: u64) {
        self.link_send(link, &format!("SERVER {}", self.config.name));
        for name in self.routes.keys() {
            if self.routes[name] != link {
                self.link_send(link, &format!("SERVER {name}"));
            }
        }
        for (&id, c) in &self.clients {
            if c.registered && c.route != Some(link) {
                self.link_send(link, &self.user_record(id));
            }
        }
        for ch in self.channels.values().filter(|ch| ch.name.starts_with('#')) {
            self.link_send(link, &self.channel_record(ch));
            for (&id, &status) in &ch.members {
                let uid = &self.clients[&id].uid;
                let version = self.member_versions.get(&(fold(&ch.name), uid.clone()));
                self.link_send(
                    link,
                    &format!(
                        "MEMBER {} {uid} {status} {} {}",
                        encode(&ch.name),
                        version.map(|v| v.0).unwrap_or(ch.revision),
                        version.map(|v| v.1.as_str()).unwrap_or(&ch.revision_by)
                    ),
                );
            }
        }
        self.link_send(link, "END");
    }

    fn remove_network_user(&mut self, id: u64, reason: &str, notify: bool) {
        self.remember_whowas(id);
        if notify {
            let recipients: Vec<_> = self
                .peers(id)
                .into_iter()
                .filter(|other| *other != id && self.clients[other].route.is_none())
                .collect();
            self.broadcast(
                recipients,
                &format!(":{} QUIT :{reason}", self.clients[&id].prefix()),
            );
        }
        let keys: Vec<_> = self.channels.keys().cloned().collect();
        for key in keys {
            self.remove_member(id, &key);
        }
        if let Some(c) = self.clients.remove(&id) {
            self.member_versions.retain(|(_, uid), _| uid != &c.uid);
        }
    }

    pub(super) fn drop_link(&mut self, id: u64, reason: &str) {
        let Some(link) = self.links.remove(&id) else {
            return;
        };
        let _ = link.socket.shutdown(Shutdown::Both);
        let names: Vec<_> = self
            .routes
            .iter()
            .filter(|(_, route)| **route == id)
            .map(|(name, _)| name.clone())
            .collect();
        let users: Vec<_> = self
            .clients
            .iter()
            .filter(|(_, c)| c.route == Some(id))
            .map(|(&id, _)| id)
            .collect();
        for user in users {
            self.remove_network_user(user, reason, true);
        }
        for name in &names {
            self.routes.remove(name);
        }
        self.net_flood(
            None,
            &format!("SPLIT {} {}", encode(&names.join(",")), encode(reason)),
        );
        eprintln!("Link {} disconnected: {reason}", link.name);
    }

    fn link_line(&mut self, link: u64, line: &str, bursting: bool) -> Option<()> {
        let p: Vec<_> = line.split(' ').collect();
        match *p.first()? {
            "SERVER" if p.len() == 2 => {
                let name = p[1];
                if name == self.links[&link].name {
                    return Some(());
                }
                if self.routes.get(name) == Some(&link) {
                    return Some(());
                }
                if name == self.config.name
                    || self.routes.contains_key(name)
                    || self.routes.len() >= 32
                    || name.len() > 63
                    || name.is_empty()
                    || !name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
                {
                    return None;
                }
                self.routes.insert(name.into(), link);
                self.net_flood(Some(link), line);
            }
            "USER" if p.len() == 10 => {
                if self.deleted_users.contains_key(p[1]) {
                    return Some(());
                }
                let home = p[1].split('!').next()?;
                let uid: Vec<_> = p[1].split('!').collect();
                if uid.len() != 3
                    || uid[1].parse::<u64>().is_err()
                    || uid[2].parse::<u64>().is_err()
                {
                    return None;
                }
                if self.routes.get(home) != Some(&link) {
                    return None;
                }
                let (nick, user, host, real, away) = (
                    decode(p[2])?,
                    decode(p[3])?,
                    decode(p[4])?,
                    decode(p[5])?,
                    decode(p[6])?,
                );
                let (modes, account) = (decode(p[8])?, decode(p[9])?);
                let oper = if p[7] == "-" {
                    None
                } else {
                    Some(OperClass::parse(p[7])?)
                };
                if !nick_valid(&nick)
                    || user.is_empty()
                    || user.len() > 12
                    || !user
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
                    || !services::host_valid(&host)
                    || real.len() > 128
                    || away.len() > 200
                    || p[1].len() > 120
                    || !modes.chars().all(|c| "iR".contains(c))
                    || !(account.is_empty() || services::account_valid(&account))
                {
                    return None;
                }
                let (invisible, identified) = (modes.contains('i'), modes.contains('R'));
                let existing = self.uid_id(p[1]);
                if existing.is_some_and(|id| self.clients[&id].route != Some(link)) {
                    return None;
                }
                if let Some(collision) = self
                    .find_nick(&nick)
                    .filter(|other| Some(*other) != existing)
                {
                    // Both partitions choose the same winner, independent of arrival order.
                    let losing_uid = if self.clients[&collision].uid.as_str() < p[1] {
                        p[1].to_string()
                    } else {
                        self.clients[&collision].uid.clone()
                    };
                    self.net_flood(None, &format!("COLLIDE {losing_uid}"));
                    self.remember_deleted(&losing_uid);
                    if losing_uid == p[1] {
                        if let Some(id) = existing {
                            self.remove_network_user(id, "Nickname collision", true);
                        }
                        return Some(());
                    }
                    self.send(collision, "ERROR :Nickname collision");
                    self.remove_network_user(collision, "Nickname collision", true);
                }
                if let Some(id) = existing {
                    if self.clients[&id].nick != nick {
                        self.remember_whowas(id);
                    }
                    let c = self.clients.get_mut(&id)?;
                    c.nick = nick;
                    c.away = away;
                    c.oper = oper;
                    (c.invisible, c.identified, c.account) = (invisible, identified, account);
                } else {
                    if self.clients.len() >= MAX_NETWORK_USERS {
                        return None;
                    }
                    self.next_id += 1;
                    let id = self.next_id;
                    let (tx, socket) = self.links[&link].handles()?;
                    let mut c = Client::new(p[1].into(), home.into(), host, tx, socket);
                    c.route = Some(link);
                    (c.oper, c.nick, c.user, c.real, c.away) = (oper, nick, user, real, away);
                    (c.invisible, c.identified, c.account) = (invisible, identified, account);
                    c.registered = true;
                    self.clients.insert(id, c);
                    self.note_peak();
                }
                self.net_flood(Some(link), line);
            }
            "CHAN" if p.len() == 12 => {
                let name = decode(p[1])?;
                let revision: u64 = p[2].parse().ok()?;
                let origin = p[3];
                if !name.starts_with('#') || !channel_valid(&name) || !server_name_valid(origin) {
                    return None;
                }
                let (flags, chan_key) = (decode(p[4])?, decode(p[5])?);
                let limit: usize = p[6].parse().ok()?;
                let (topic, topic_by) = (decode(p[7])?, decode(p[8])?);
                let (topic_at, created): (u64, u64) = (p[9].parse().ok()?, p[10].parse().ok()?);
                let bans = decode(p[11])?;
                let bans: Vec<String> = bans
                    .split(',')
                    .filter(|b| !b.is_empty())
                    .map(String::from)
                    .collect();
                if topic.len() > 300
                    || topic_by.len() > 128
                    || !flags.chars().all(|c| "imnst".contains(c))
                    || !(chan_key.is_empty() || channel::key_valid(&chan_key))
                    || bans.len() > channel::MAX_BANS
                    || bans.iter().any(|b| b.len() > 110)
                {
                    return None;
                }
                let key = fold(&name);
                if self.channels.len() >= MAX_NETWORK_USERS * MAX_CHANNELS
                    && !self.channels.contains_key(&key)
                {
                    return None;
                }
                let ch = self
                    .channels
                    .entry(key)
                    .or_insert_with(|| placeholder_channel(&name));
                if (revision, origin) > (ch.revision, ch.revision_by.as_str()) {
                    ch.revision = revision;
                    ch.revision_by = origin.into();
                    ch.topic = topic;
                    ch.topic_by = topic_by;
                    ch.topic_at = topic_at;
                    ch.set_flags(&flags);
                    (ch.key, ch.limit, ch.bans, ch.created) = (chan_key, limit, bans, created);
                }
                self.net_flood(Some(link), line);
            }
            "MEMBER" if p.len() == 6 => {
                let name = decode(p[1])?;
                if !name.starts_with('#') || !channel_valid(&name) {
                    return None;
                }
                let Some(id) = self.uid_id(p[2]) else {
                    return Some(());
                };
                // Membership records may be sent by any trusted server (KICK/SAMODE).
                let key = fold(&name);
                let revision = p[4].parse::<u64>().ok()?;
                let origin = p[5];
                if !server_name_valid(origin) {
                    return None;
                }
                let version_key = (key.clone(), p[2].to_string());
                if self
                    .member_versions
                    .get(&version_key)
                    .is_some_and(|old| (revision, origin) <= (old.0, old.1.as_str()))
                {
                    self.net_flood(Some(link), line);
                    return Some(());
                }
                if self.member_versions.len() >= MAX_NETWORK_USERS * MAX_CHANNELS * 2
                    && !self.member_versions.contains_key(&version_key)
                {
                    self.member_versions.retain(|(channel, uid), _| {
                        self.channels.get(channel).is_some_and(|ch| {
                            ch.members.keys().any(|id| self.clients[id].uid == *uid)
                        })
                    });
                }
                self.member_versions
                    .insert(version_key, (revision, origin.into()));
                if p[3] == "-" {
                    self.remove_member(id, &key);
                } else {
                    // Status bits: 1 = channel operator, 2 = voice.
                    let status: u8 = p[3].parse().ok().filter(|s| *s <= 3)?;
                    if self
                        .channels
                        .values()
                        .filter(|c| c.members.contains_key(&id))
                        .count()
                        >= MAX_CHANNELS
                        && !self
                            .channels
                            .get(&key)
                            .is_some_and(|c| c.members.contains_key(&id))
                    {
                        return None;
                    }
                    if self.channels.len() >= MAX_NETWORK_USERS * MAX_CHANNELS
                        && !self.channels.contains_key(&key)
                    {
                        return None;
                    }
                    // A JOIN can race a local PART that emptied and deleted the channel,
                    // so the peer sends no CHAN. shortcut: modes/topic stay at defaults
                    // until the next CHAN or relink; send CHAN with MEMBER if that matters.
                    let ch = self
                        .channels
                        .entry(key.clone())
                        .or_insert_with(|| placeholder_channel(&name));
                    let new = ch.members.insert(id, status).is_none();
                    if bursting && new {
                        // Burst memberships carry no JOIN line, and servers further on
                        // receive them as ordinary updates, so this server announces the
                        // join to every member not on the bursting side.
                        let recipients: Vec<_> = self.channels[&key]
                            .members
                            .keys()
                            .copied()
                            .filter(|other| *other != id && self.clients[other].route != Some(link))
                            .collect();
                        self.broadcast(
                            recipients,
                            &format!(":{} JOIN {}", self.clients[&id].prefix(), name),
                        );
                    }
                }
                self.net_flood(Some(link), line);
            }
            "WIRE" if p.len() == 3 => {
                let Some(id) = self.uid_id(p[1]) else {
                    return Some(());
                };
                if self.clients[&id].route == Some(link) {
                    return None;
                }
                let text = decode(p[2])?;
                if text.len() > MAX_LINE || !text.starts_with(':') && !text.starts_with("ERROR ") {
                    return None;
                }
                self.send(id, &text);
            }
            "REMOVE" if p.len() == 3 => {
                let reason = decode(p[2])?;
                self.remember_deleted(p[1]);
                if let Some(id) = self.uid_id(p[1]) {
                    self.remove_network_user(id, &reason, false);
                }
                self.net_flood(Some(link), line);
            }
            "COLLIDE" if p.len() == 2 => {
                self.remember_deleted(p[1]);
                if let Some(id) = self.uid_id(p[1]) {
                    self.send(id, "ERROR :Nickname collision");
                    self.remove_network_user(id, "Nickname collision", true);
                }
                self.net_flood(Some(link), line);
            }
            "SPLIT" if p.len() == 3 => {
                let names = decode(p[1])?;
                let reason = decode(p[2])?;
                let names: Vec<_> = names.split(',').collect();
                if names
                    .iter()
                    .any(|name| self.routes.get(*name).is_some_and(|route| *route != link))
                {
                    return None;
                }
                let ids: Vec<_> = self
                    .clients
                    .iter()
                    .filter(|(_, c)| names.contains(&c.home.as_str()))
                    .map(|(&id, _)| id)
                    .collect();
                for id in ids {
                    self.remove_network_user(id, &reason, true);
                }
                for name in names {
                    self.routes.remove(name);
                }
                self.net_flood(Some(link), line);
            }
            "FORCE" if p.len() == 4 => {
                // The actor is an override operator's uid, or a server (services)
                // reached through this link.
                let source = if let Some(actor) = self.uid_id(p[1]) {
                    if self.clients[&actor].route != Some(link) || !self.can_override(actor) {
                        return None;
                    }
                    self.clients[&actor].prefix()
                } else if self.routes.get(p[1]) == Some(&link) {
                    p[1].to_string()
                } else {
                    return None;
                };
                let target = self.uid_id(p[2])?;
                if self.clients[&target].route == Some(link) {
                    return None;
                }
                let action = decode(p[3])?;
                let msg = parse(&action)?;
                let valid = match (msg.command.as_str(), msg.params.as_slice()) {
                    ("JOIN" | "PART" | "NICK", [_]) => true,
                    ("UMODE", [mode]) => matches!(mode.as_str(), "+R" | "-R"),
                    ("ACCOUNT", []) => true,
                    ("ACCOUNT", [account]) => services::account_valid(account),
                    _ => false,
                };
                if !valid {
                    return None;
                }
                if let Some(route) = self.clients[&target].route {
                    self.link_send(route, line);
                } else {
                    self.replicated(target, |server| server.force(target, &msg, &source));
                }
            }
            "INVITED" if p.len() == 3 => {
                // Routed to the invitee's home server, which checks its JOINs.
                let Some(target) = self.uid_id(p[1]) else {
                    return Some(());
                };
                let key = decode(p[2])?;
                if !channel_valid(&key) || self.clients[&target].route == Some(link) {
                    return None;
                }
                self.record_invite(target, &key);
            }
            "END" if p.len() == 1 => {
                self.channels.retain(|_, ch| !ch.members.is_empty());
            }
            _ => return None,
        }
        Some(())
    }
}

// Reading one byte preserves the handshake boundary and caps memory even for a
// peer that never supplies a newline. Buffered reads keep steady-state efficient.
/// Mutual challenge-response: each side proves it knows the shared secret with an
/// HMAC over both sides' nonces, so the secret never crosses the wire and a
/// recorded handshake cannot be replayed. The connecting side proves itself first,
/// so an unauthenticated caller learns only a nonce. Returns the peer's known
/// server names (hex-decoded, comma separated), used to reject cycles.
///
///   connecting: YAMLINK <version> <name> <nonce> <hex-names>
///   accepting:  CHALLENGE <nonce>
///   connecting: PROOF <proof of connect>
///   accepting:  YAMLINK <version> <name> <nonce> <hex-names> <proof of accept>
fn handshake(
    socket: &mut TcpStream,
    reader: &mut impl BufRead,
    state: &Arc<Mutex<Server>>,
    config: &LinkConfig,
    first: Option<String>,
) -> io::Result<String> {
    let denied = || {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Link authentication failed",
        )
    };
    let (me, known) = {
        let state = state.lock().unwrap();
        let mut names: Vec<_> = state.routes.keys().cloned().collect();
        names.push(state.config.name.clone());
        (state.config.name.clone(), encode(&names.join(",")))
    };
    let secret = config.password.as_str();
    let ours = crypto::nonce();
    if let Some(first) = first {
        // Accepting: the caller's name and source IP already selected `config`.
        let p: Vec<_> = first.split(' ').collect();
        if p.len() != 5 || p[0] != "YAMLINK" || p[1] != PROTOCOL_VERSION || p[2] != config.name {
            return Err(denied());
        }
        let theirs = p[3];
        let names = decode(p[4])
            .filter(|_| crypto::nonce_valid(theirs))
            .ok_or_else(denied)?;
        socket.write_all(format!("CHALLENGE {ours}\r\n").as_bytes())?;
        let proof = read_line(reader)?;
        let expected = crypto::link_proof(secret, "connect", &ours, theirs, &config.name);
        if !proof
            .strip_prefix("PROOF ")
            .is_some_and(|proof| crypto::proof_matches(&expected, proof))
        {
            return Err(denied());
        }
        let proof = crypto::link_proof(secret, "accept", theirs, &ours, &me);
        let hello = format!("YAMLINK {PROTOCOL_VERSION} {me} {ours} {known} {proof}\r\n");
        socket.write_all(hello.as_bytes())?;
        Ok(names)
    } else {
        socket
            .write_all(format!("YAMLINK {PROTOCOL_VERSION} {me} {ours} {known}\r\n").as_bytes())?;
        let challenge = read_line(reader)?;
        let theirs = challenge
            .strip_prefix("CHALLENGE ")
            .filter(|nonce| crypto::nonce_valid(nonce))
            .ok_or_else(denied)?
            .to_string();
        let proof = crypto::link_proof(secret, "connect", &theirs, &ours, &me);
        socket.write_all(format!("PROOF {proof}\r\n").as_bytes())?;
        let hello = read_line(reader)?;
        let p: Vec<_> = hello.split(' ').collect();
        let expected = crypto::link_proof(secret, "accept", &ours, &theirs, &config.name);
        if p.len() != 6
            || p[0] != "YAMLINK"
            || p[1] != PROTOCOL_VERSION
            || p[2] != config.name
            || p[3] != theirs
            || !crypto::proof_matches(&expected, p[5])
        {
            return Err(denied());
        }
        decode(p[4]).ok_or_else(denied)
    }
}

pub(super) fn read_line(reader: &mut impl BufRead) -> io::Result<String> {
    let mut bytes = Vec::new();
    let started = Instant::now();
    loop {
        if started.elapsed() > Duration::from_secs(10) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut byte = [0];
        let count = reader.read(&mut byte).map_err(|err| {
            if !bytes.is_empty()
                && matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                )
            {
                io::Error::from(io::ErrorKind::InvalidData)
            } else {
                err
            }
        })?;
        if count == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        if byte[0] == b'\n' {
            break;
        }
        if bytes.len() >= LINK_LINE {
            return Err(io::ErrorKind::InvalidData.into());
        }
        bytes.push(byte[0]);
    }
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    String::from_utf8(bytes).map_err(|_| io::ErrorKind::InvalidData.into())
}

fn session(
    mut socket: TcpStream,
    state: Arc<Mutex<Server>>,
    expected: Option<LinkConfig>,
) -> io::Result<()> {
    socket.set_read_timeout(Some(Duration::from_secs(10)))?;
    socket.set_write_timeout(Some(Duration::from_secs(5)))?;
    socket.set_nodelay(true)?;
    let remote_ip = socket.peer_addr()?.ip();
    let mut reader = BufReader::new(socket.try_clone()?);
    // Inbound waits for the caller's identity before selecting its per-peer secret.
    let incoming = if expected.is_none() {
        Some(read_line(&mut reader)?)
    } else {
        None
    };
    // Services (such as Anope) speak the ngIRCd protocol, which starts with PASS.
    if let Some(first) = incoming.as_ref().filter(|l| !l.starts_with("YAMLINK ")) {
        return services::session(socket, reader, state, first.clone(), remote_ip);
    }
    let config = {
        let state = state.lock().unwrap();
        if let Some(config) = expected {
            config
        } else {
            let name = incoming
                .as_ref()
                .and_then(|s| s.split(' ').nth(2))
                .unwrap_or("");
            state
                .config
                .links
                .iter()
                .find(|l| l.name == name && l.incoming_ip == remote_ip)
                .cloned()
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::PermissionDenied, "Unknown peer or IP")
                })?
        }
    };
    let names = handshake(&mut socket, &mut reader, &state, &config, incoming)?;
    let names: Vec<_> = names.split(',').collect();
    let (tx, rx) = mpsc::sync_channel(LINK_QUEUE);
    let id;
    {
        let mut state = state.lock().unwrap();
        if state.disabled_links.contains(&config.name)
            || state.links.len() >= 8
            || !names.contains(&config.name.as_str())
            || names.iter().any(|name| {
                fold(name) == fold(&state.config.name)
                    || state.routes.keys().any(|known| fold(known) == fold(name))
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Duplicate server or cycle in network",
            ));
        }
        state.next_id += 1;
        id = state.next_id;
        state.links.insert(
            id,
            Link::new(config.name.clone(), tx, socket.try_clone()?, None),
        );
        state.routes.insert(config.name.clone(), id);
        state.net_flood(Some(id), &format!("SERVER {}", config.name));
        state.burst(id);
    }
    eprintln!("Link {} connected", config.name);
    spawn_writer(Arc::clone(&state), id, socket.try_clone()?, rx);
    // A quiet link gets a heartbeat from the reader on timeout; its reply must
    // arrive within another timeout. Ordinary traffic also proves liveness.
    let mut waiting = false;
    let mut bursting = true;
    let result = loop {
        match read_line(&mut reader) {
            Ok(line) if line == "PING" => {
                state.lock().unwrap().link_send(id, "PONG");
                waiting = false;
            }
            Ok(line) if line == "PONG" => {
                waiting = false;
            }
            Ok(line) => {
                waiting = false;
                let mut server = state.lock().unwrap();
                if !server.links.contains_key(&id) {
                    break Ok(());
                }
                if server.link_line(id, &line, bursting).is_none() {
                    break Err(io::ErrorKind::InvalidData.into());
                }
                if line == "END" {
                    bursting = false;
                }
            }
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) && !waiting =>
            {
                state.lock().unwrap().link_send(id, "PING");
                waiting = true;
            }
            Err(err) => break Err(err),
        }
    };
    state.lock().unwrap().drop_link(id, "Server link lost");
    result
}

/// Writes a link's queued lines until it closes, then drops the link.
pub(super) fn spawn_writer(
    state: Arc<Mutex<Server>>,
    id: u64,
    mut writer: TcpStream,
    rx: mpsc::Receiver<String>,
) {
    thread::spawn(move || {
        for line in rx {
            if writer.write_all(line.as_bytes()).is_err() {
                break;
            }
        }
        let _ = writer.shutdown(Shutdown::Both);
        state.lock().unwrap().drop_link(id, "Link write failure");
    });
}

pub(super) fn start(state: Arc<Mutex<Server>>) -> io::Result<()> {
    let config = state.lock().unwrap().config.clone();
    let Some(address) = config.link_listen else {
        return Ok(());
    };
    let listener = TcpListener::bind(&address)?;
    eprintln!("YamIRCd link listener on {}", listener.local_addr()?);
    let incoming_state = Arc::clone(&state);
    thread::spawn(move || {
        for socket in listener.incoming().flatten() {
            let state = Arc::clone(&incoming_state);
            // Only allow configured source IPs; at most eight concurrent handshakes.
            let permitted = {
                let state = state.lock().unwrap();
                let links = state.config.links.iter().map(|l| l.incoming_ip);
                let services = state.config.services.iter().map(|s| s.incoming_ip);
                links
                    .chain(services)
                    .any(|ip| socket.peer_addr().is_ok_and(|p| p.ip() == ip))
            };
            if !permitted {
                continue;
            }
            let permit = Arc::clone(&incoming_state);
            {
                let mut state = permit.lock().unwrap();
                if state.handshakes >= 8 {
                    continue;
                }
                state.handshakes += 1;
            }
            thread::spawn(move || {
                if let Err(err) = session(socket, state, None) {
                    eprintln!("Incoming link rejected: {err}");
                }
                permit.lock().unwrap().handshakes -= 1;
            });
        }
    });
    for link in config.links.into_iter().filter(|l| l.address.is_some()) {
        let state = Arc::clone(&state);
        thread::spawn(move || loop {
            let connect = {
                let state = state.lock().unwrap();
                !state.disabled_links.contains(&link.name) && !state.routes.contains_key(&link.name)
            };
            if connect {
                if let Ok(socket) =
                    TcpStream::connect_timeout(&link.address.unwrap(), Duration::from_secs(3))
                {
                    if let Err(err) = session(socket, Arc::clone(&state), Some(link.clone())) {
                        eprintln!("Outgoing link {} failed: {err}", link.name);
                    }
                }
            }
            thread::sleep(Duration::from_secs(2));
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wire_encoding() {
        for text in ["", "space and :colon", "héllo"] {
            assert_eq!(decode(&encode(text)).as_deref(), Some(text));
        }
        assert!(decode("xx").is_none());
        assert!(decode("0a").is_none());
        assert!(decode("f").is_none());
    }

    #[test]
    fn member_for_deleted_channel_keeps_link() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let _remote = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (socket, _) = listener.accept().unwrap();
        let (tx, _rx) = mpsc::sync_channel(1);
        let mut server = Server::new(Config::default());
        let mut client = Client::new(
            "b.test!1!1".into(),
            "b.test".into(),
            "127.0.0.1".into(),
            tx,
            socket,
        );
        client.route = Some(7);
        (client.nick, client.user, client.real) =
            ("Remote".into(), "remote".into(), "Remote".into());
        client.registered = true;
        server.clients.insert(1, client);
        // No CHAN precedes this MEMBER: the channel was deleted locally by a racing PART.
        let line = format!("MEMBER {} b.test!1!1 0 5 b.test", encode("#X"));
        assert!(server.link_line(7, &line, false).is_some());
        assert_eq!(server.channels["#x"].members.get(&1), Some(&0));
        assert_eq!(server.channels["#x"].name, "#X");

        // v2 records carry modes, key, limit, bans and voice.
        let chan = |flags: &str| {
            format!(
                "CHAN {} 10 b.test {} {} 5 - - 0 100 {}",
                encode("#X"),
                encode(flags),
                encode("beer"),
                encode("a!*@*,b!*@*")
            )
        };
        assert!(server.link_line(7, &chan("imt"), false).is_some());
        let ch = &server.channels["#x"];
        assert_eq!(
            (ch.flags().as_str(), ch.key.as_str(), ch.limit),
            ("imt", "beer", 5)
        );
        assert_eq!((ch.bans.len(), ch.created), (2, 100));
        let voice = format!("MEMBER {} b.test!1!1 2 6 b.test", encode("#X"));
        assert!(server.link_line(7, &voice, false).is_some());
        assert_eq!(server.channels["#x"].members.get(&1), Some(&channel::VOICE));
        assert!(server.link_line(7, &chan("x"), false).is_none());
    }
}
