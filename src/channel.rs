//! Channel state, join restrictions, INVITE, and the channel MODE command.
use super::*;

pub(crate) const OP: u8 = 1;
pub(crate) const VOICE: u8 = 2;
pub(crate) const MAX_BANS: usize = 60;
const MAX_INVITES: usize = 32;

#[derive(Clone, PartialEq)]
pub(crate) struct Channel {
    pub(crate) name: String,
    /// Member status bits: `OP` and `VOICE`.
    pub(crate) members: BTreeMap<u64, u8>,
    pub(crate) topic: String,
    pub(crate) topic_by: String,
    pub(crate) topic_at: u64,
    pub(crate) no_external: bool,
    pub(crate) protected_topic: bool,
    pub(crate) invite_only: bool,
    pub(crate) moderated: bool,
    pub(crate) secret: bool,
    pub(crate) key: String,
    /// 0 means no limit.
    pub(crate) limit: usize,
    pub(crate) bans: Vec<String>,
    pub(crate) created: u64,
    pub(crate) revision: u64,
    pub(crate) revision_by: String,
}

impl Channel {
    /// New channels start `+nt`.
    pub(crate) fn new(name: &str, created: u64, revision: u64, revision_by: String) -> Self {
        Self {
            name: name.into(),
            members: BTreeMap::new(),
            topic: String::new(),
            topic_by: String::new(),
            topic_at: 0,
            no_external: true,
            protected_topic: true,
            invite_only: false,
            moderated: false,
            secret: false,
            key: String::new(),
            limit: 0,
            bans: Vec::new(),
            created,
            revision,
            revision_by,
        }
    }

    pub(crate) fn is_op(&self, id: u64) -> bool {
        self.members.get(&id).is_some_and(|s| s & OP != 0)
    }

    /// Everything replicated in a CHAN record (members travel separately).
    pub(crate) fn same_meta(&self, other: &Channel) -> bool {
        self.flags() == other.flags()
            && self.key == other.key
            && self.limit == other.limit
            && self.bans == other.bans
            && self.topic == other.topic
            && self.topic_by == other.topic_by
    }

    /// Parameterless modes in CHANMODES order: `imnst`.
    pub(crate) fn flags(&self) -> String {
        [
            ('i', self.invite_only),
            ('m', self.moderated),
            ('n', self.no_external),
            ('s', self.secret),
            ('t', self.protected_topic),
        ]
        .iter()
        .filter(|(_, on)| *on)
        .map(|(c, _)| *c)
        .collect()
    }

    pub(crate) fn set_flags(&mut self, flags: &str) {
        self.invite_only = flags.contains('i');
        self.moderated = flags.contains('m');
        self.no_external = flags.contains('n');
        self.secret = flags.contains('s');
        self.protected_topic = flags.contains('t');
    }

    /// `+flags[k][l] [key] [limit]` for RPL_CHANNELMODEIS; the key only for members.
    fn mode_reply(&self, show_key: bool) -> String {
        let mut modes = format!("+{}", self.flags());
        let mut args = String::new();
        if !self.key.is_empty() {
            modes.push('k');
            args.push(' ');
            args.push_str(if show_key { &self.key } else { "*" });
        }
        if self.limit > 0 {
            modes.push('l');
            args.push_str(&format!(" {}", self.limit));
        }
        modes + &args
    }
}

/// NAMES/WHO prefix for member status; only the highest unless multi-prefix.
pub(crate) fn status_prefix(status: u8, multi: bool) -> &'static str {
    match (status & OP != 0, status & VOICE != 0, multi) {
        (true, true, true) => "@+",
        (true, _, _) => "@",
        (false, true, _) => "+",
        _ => "",
    }
}

/// Keys follow RFC 2812: 1-23 printable ASCII characters, no spaces (or commas,
/// which separate keys in JOIN).
pub(crate) fn key_valid(key: &str) -> bool {
    !key.is_empty() && key.len() <= 23 && key.bytes().all(|b| b > b' ' && b < 127 && b != b',')
}

/// Completes `nick`, `user@host` or `nick!user` to a full `nick!user@host` mask.
pub(crate) fn normalize_mask(mask: &str) -> String {
    match (mask.contains('!'), mask.contains('@')) {
        (true, true) => mask.into(),
        (false, true) => format!("*!{mask}"),
        (true, false) => format!("{mask}@*"),
        (false, false) => format!("{mask}!*@*"),
    }
}

/// Appends a mode letter, adding the sign only when it changes.
pub(crate) fn push_mode(modes: &mut String, adding: bool, mode: char) {
    let sign = if adding { '+' } else { '-' };
    if modes.chars().rev().find(|c| matches!(c, '+' | '-')) != Some(sign) {
        modes.push(sign);
    }
    modes.push(mode);
}

impl Server {
    /// Secret channels are hidden from everyone but their members.
    pub(crate) fn visible(&self, ch: &Channel, id: u64) -> bool {
        !ch.secret || ch.members.contains_key(&id)
    }

    fn banned(&self, ch: &Channel, id: u64) -> bool {
        let identity = fold(&self.clients[&id].prefix());
        ch.bans
            .iter()
            .any(|ban| oper::matches(&fold(ban), &identity))
    }

    /// Joins one channel; `forced` (SAJOIN) skips key, invite, ban and limit checks.
    pub(crate) fn join_channel(&mut self, id: u64, name: &str, key: Option<&str>, forced: bool) {
        let folded = fold(name);
        if !channel_valid(name) {
            self.numeric(id, 476, &format!("{name} :Bad channel mask"));
            return;
        }
        if self
            .channels
            .get(&folded)
            .is_some_and(|c| c.members.contains_key(&id))
        {
            return;
        }
        if self
            .channels
            .values()
            .filter(|c| c.members.contains_key(&id))
            .count()
            >= MAX_CHANNELS
        {
            self.numeric(
                id,
                405,
                &format!("{name} :You have joined too many channels"),
            );
            return;
        }
        if let Some(ch) = self.channels.get(&folded).filter(|_| !forced) {
            // An invitation overrides +i, +b and +l (Modern), but not a key.
            let invited = self.clients[&id].invites.contains(&folded);
            let error = if !ch.key.is_empty() && key != Some(ch.key.as_str()) {
                Some((475, "Cannot join channel (+k)"))
            } else if invited {
                None
            } else if self.banned(ch, id) {
                Some((474, "Cannot join channel (+b)"))
            } else if ch.invite_only {
                Some((473, "Cannot join channel (+i)"))
            } else if ch.limit > 0 && ch.members.len() >= ch.limit {
                Some((471, "Cannot join channel (+l)"))
            } else {
                None
            };
            if let Some((code, text)) = error {
                self.numeric(id, code, &format!("{} :{text}", ch.name));
                return;
            }
        }
        self.clients.get_mut(&id).unwrap().invites.remove(&folded);
        let (now, server) = (network::millis(), self.config.name.clone());
        let service = self.is_service(id);
        let ch = self
            .channels
            .entry(folded.clone())
            .or_insert_with(|| Channel::new(name, timestamp(), now, server));
        // Services set their own status, as they track it themselves.
        let status = if ch.members.is_empty() && !service {
            OP
        } else {
            0
        };
        ch.members.insert(id, status);
        let ch = &self.channels[&folded];
        self.broadcast(
            ch.members.keys().copied(),
            &format!(":{} JOIN {}", self.clients[&id].prefix(), ch.name),
        );
        if !ch.topic.is_empty() {
            self.topic_reply(id, &folded);
        }
        self.names(id, &folded, &ch.name);
    }

    pub(crate) fn invite(&mut self, id: u64, p: &[String]) {
        let Some(other) = self
            .find_nick(&p[0])
            .filter(|other| self.clients[other].registered)
        else {
            self.numeric(id, 401, &format!("{} :No such nick", p[0]));
            return;
        };
        let key = fold(&p[1]);
        if let Some(ch) = self.channels.get(&key) {
            if !ch.members.contains_key(&id) && !self.privileged(id) {
                self.numeric(id, 442, &format!("{} :You're not on that channel", p[1]));
                return;
            }
            if ch.invite_only && !ch.is_op(id) && !self.privileged(id) {
                self.numeric(
                    id,
                    482,
                    &format!("{} :You're not channel operator", ch.name),
                );
                return;
            }
            if ch.members.contains_key(&other) {
                self.numeric(
                    id,
                    443,
                    &format!("{} {} :is already on channel", p[0], p[1]),
                );
                return;
            }
        }
        if !channel_valid(&p[1]) {
            self.numeric(id, 476, &format!("{} :Bad channel mask", p[1]));
            return;
        }
        self.numeric(id, 341, &format!("{} {}", self.clients[&other].nick, p[1]));
        self.send(
            other,
            &format!(
                ":{} INVITE {} :{}",
                self.clients[&id].prefix(),
                self.clients[&other].nick,
                p[1]
            ),
        );
        self.record_invite(other, &key);
    }

    /// Invitations are checked by the invitee's home server, which handles its JOINs.
    pub(crate) fn record_invite(&mut self, id: u64, key: &str) {
        if let Some(route) = self.clients[&id].route {
            let uid = &self.clients[&id].uid;
            self.link_send(route, &format!("INVITED {uid} {}", network::encode(key)));
            return;
        }
        let invites = &mut self.clients.get_mut(&id).unwrap().invites;
        if invites.len() >= MAX_INVITES {
            invites.pop_first();
        }
        invites.insert(key.into());
    }

    fn ban_list(&self, id: u64, key: &str) {
        let ch = &self.channels[key];
        for ban in &ch.bans {
            self.numeric(id, 367, &format!("{} {ban}", ch.name));
        }
        self.numeric(id, 368, &format!("{} :End of channel ban list", ch.name));
    }

    pub(crate) fn channel_mode(&mut self, id: u64, p: &[String]) {
        let key = fold(&p[0]);
        let Some(ch) = self.channels.get(&key) else {
            self.numeric(id, 403, &format!("{} :No such channel", p[0]));
            return;
        };
        if p.len() == 1 {
            let show_key = ch.members.contains_key(&id) || self.privileged(id);
            self.numeric(id, 324, &format!("{} {}", ch.name, ch.mode_reply(show_key)));
            self.numeric(id, 329, &format!("{} {}", ch.name, ch.created));
            return;
        }
        let may_change = ch.is_op(id) || self.privileged(id);
        let (mut adding, mut arg, mut denied) = (true, 2, false);
        let (mut modes, mut args) = (String::new(), Vec::new());
        for mode in p[1].chars() {
            match mode {
                '+' => adding = true,
                '-' => adding = false,
                _ => {}
            }
            if matches!(mode, '+' | '-') {
                continue;
            }
            // CHANMODES=b,k,l,imnst: b, k (and o, v) always take a parameter, l when set.
            let param = if matches!(mode, 'b' | 'k' | 'o' | 'v') || (mode == 'l' && adding) {
                let value = p.get(arg).cloned();
                arg += usize::from(value.is_some());
                value
            } else {
                None
            };
            if !"biklmnostv".contains(mode) {
                self.numeric(id, 472, &format!("{mode} :is unknown mode char to me"));
                continue;
            }
            if mode == 'b' && param.is_none() {
                self.ban_list(id, &key);
                continue;
            }
            if !may_change {
                denied = true;
                continue;
            }
            if param.is_none() && (matches!(mode, 'o' | 'v') || (mode == 'l' && adding)) {
                self.numeric(id, 461, "MODE :Not enough parameters");
                continue;
            }
            let target = match (mode, &param) {
                ('o' | 'v', Some(nick)) => match self.find_nick(nick) {
                    Some(target) => Some((target, self.clients[&target].nick.clone())),
                    None => {
                        self.numeric(id, 401, &format!("{nick} :No such nick"));
                        continue;
                    }
                },
                _ => None,
            };
            let ch = self.channels.get_mut(&key).unwrap();
            // Ok(Some(echo-param?)) when the mode changed, Ok(None) for a no-op.
            let outcome: Result<Option<Option<String>>, (u16, String)> = match mode {
                'i' | 'm' | 'n' | 's' | 't' => {
                    let flag = match mode {
                        'i' => &mut ch.invite_only,
                        'm' => &mut ch.moderated,
                        'n' => &mut ch.no_external,
                        's' => &mut ch.secret,
                        _ => &mut ch.protected_topic,
                    };
                    Ok((*flag != adding).then(|| {
                        *flag = adding;
                        None
                    }))
                }
                'k' if adding => match param {
                    Some(k) if key_valid(&k) => Ok((ch.key != k).then(|| {
                        ch.key = k.clone();
                        Some(k)
                    })),
                    // An empty or missing key is invalid too; the parameter shows as `*`.
                    _ => Err((696, format!("{} k * :Invalid key", ch.name))),
                },
                'k' => Ok((!ch.key.is_empty()).then(|| {
                    ch.key.clear();
                    Some("*".into())
                })),
                'l' if adding => {
                    let value = param.unwrap();
                    match value.parse::<usize>() {
                        Ok(limit) if limit > 0 => Ok((ch.limit != limit).then(|| {
                            ch.limit = limit;
                            Some(value)
                        })),
                        _ => Err((
                            696,
                            format!(
                                "{} l {} :Invalid limit",
                                ch.name,
                                if value.is_empty() { "*" } else { &value }
                            ),
                        )),
                    }
                }
                'l' => Ok((ch.limit != 0).then(|| {
                    ch.limit = 0;
                    None
                })),
                'b' => {
                    let mask = normalize_mask(truncate(&param.unwrap(), 100));
                    let folded = fold(&mask);
                    if mask.contains(',') {
                        Err((696, format!("{} b {mask} :Invalid ban mask", ch.name)))
                    } else if adding {
                        if ch.bans.iter().any(|b| fold(b) == folded) {
                            Ok(None)
                        } else if ch.bans.len() >= MAX_BANS {
                            Err((478, format!("{} {mask} :Channel ban list is full", ch.name)))
                        } else {
                            ch.bans.push(mask.clone());
                            Ok(Some(Some(mask)))
                        }
                    } else {
                        // Unsetting matches case-insensitively, as clients may retype a ban.
                        let before = ch.bans.len();
                        ch.bans.retain(|b| fold(b) != folded);
                        Ok((ch.bans.len() < before).then_some(Some(mask)))
                    }
                }
                _ => {
                    let (target, nick) = target.unwrap();
                    let bit = if mode == 'o' { OP } else { VOICE };
                    match ch.members.get_mut(&target) {
                        Some(status) => {
                            let new = if adding {
                                *status | bit
                            } else {
                                *status & !bit
                            };
                            Ok((new != *status).then(|| {
                                *status = new;
                                Some(nick)
                            }))
                        }
                        None => Err((
                            441,
                            format!("{nick} {} :They aren't on that channel", ch.name),
                        )),
                    }
                }
            };
            match outcome {
                Ok(Some(param)) => {
                    push_mode(&mut modes, adding, mode);
                    args.extend(param);
                }
                Ok(None) => {}
                Err((code, text)) => self.numeric(id, code, &text),
            }
        }
        if denied {
            self.numeric(id, 482, &format!("{} :You're not channel operator", p[0]));
        }
        if !modes.is_empty() {
            let ch = &self.channels[&key];
            let args: String = args.iter().map(|a| format!(" {a}")).collect();
            self.broadcast(
                ch.members.keys().copied(),
                &format!(
                    ":{} MODE {} {modes}{args}",
                    self.clients[&id].prefix(),
                    ch.name
                ),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_helpers() {
        let mut modes = String::new();
        for (adding, mode) in [
            (true, 'i'),
            (true, 'l'),
            (false, 'o'),
            (false, 'v'),
            (true, 'k'),
        ] {
            push_mode(&mut modes, adding, mode);
        }
        assert_eq!(modes, "+il-ov+k");
        assert_eq!(normalize_mask("bar"), "bar!*@*");
        assert_eq!(normalize_mask("u@h"), "*!u@h");
        assert_eq!(normalize_mask("n!u"), "n!u@*");
        assert_eq!(normalize_mask("n!u@h"), "n!u@h");
        assert!(key_valid("beer"));
        for bad in ["", " ", "has space", "a,b", &"x".repeat(24)] {
            assert!(!key_valid(bad), "{bad:?}");
        }
        assert_eq!(status_prefix(OP | VOICE, true), "@+");
        assert_eq!(status_prefix(OP | VOICE, false), "@");
        assert_eq!(status_prefix(VOICE, false), "+");
        let mut ch = Channel::new("#c", 1, 1, "s".into());
        ch.set_flags("is");
        assert_eq!(ch.flags(), "is");
        ch.key = "k".into();
        ch.limit = 5;
        assert_eq!(ch.mode_reply(true), "+iskl k 5");
        assert_eq!(ch.mode_reply(false), "+iskl * 5");
    }
}
