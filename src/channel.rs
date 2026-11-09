//! Channel state, join restrictions, bans and extbans, INVITE, KNOCK, KICK, flood
//! protection, and the channel MODE command.
use super::*;
use modes::Timed;

pub(crate) const OP: u8 = 1;
pub(crate) const VOICE: u8 = 2;
pub(crate) const HALFOP: u8 = 4;
pub(crate) const ADMIN: u8 = 8;
pub(crate) const OWNER: u8 = 16;
/// A delayed-join (+D) member not yet shown to the channel.
pub(crate) const HIDDEN: u8 = 32;
pub(crate) const MAX_BANS: usize = 60;
const MAX_INVITES: usize = 32;
/// Status modes, highest first: bit, mode letter, NAMES prefix.
pub(crate) const STATUSES: [(u8, char, char); 5] = [
    (OWNER, 'q', '~'),
    (ADMIN, 'a', '&'),
    (OP, 'o', '@'),
    (HALFOP, 'h', '%'),
    (VOICE, 'v', '+'),
];

/// 5 owner, 4 admin, 3 operator, 2 halfop, 1 voice, 0 none.
pub(crate) fn rank(status: u8) -> u8 {
    STATUSES
        .iter()
        .position(|(bit, ..)| status & bit != 0)
        .map_or(0, |i| 5 - i as u8)
}

/// What a ban stops.
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Check {
    Join,
    Speak,
    Nick,
}

#[derive(Clone, PartialEq)]
pub(crate) struct Channel {
    pub(crate) name: String,
    /// Member status bits: `STATUSES` and `HIDDEN`.
    pub(crate) members: BTreeMap<u64, u8>,
    pub(crate) topic: String,
    pub(crate) topic_by: String,
    pub(crate) topic_at: u64,
    /// Modes without a parameter, letters from `modes::CHAN_FLAGS`.
    pub(crate) modes: BTreeSet<char>,
    pub(crate) key: String,
    /// 0 means no limit.
    pub(crate) limit: usize,
    /// L, j, f, F and H with their parameters.
    pub(crate) params: BTreeMap<char, String>,
    pub(crate) bans: Vec<String>,
    pub(crate) excepts: Vec<String>,
    pub(crate) invex: Vec<String>,
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
            modes: "nt".chars().collect(),
            key: String::new(),
            limit: 0,
            params: BTreeMap::new(),
            bans: Vec::new(),
            excepts: Vec::new(),
            invex: Vec::new(),
            created,
            revision,
            revision_by,
        }
    }

    pub(crate) fn has(&self, mode: char) -> bool {
        self.modes.contains(&mode)
    }

    pub(crate) fn rank(&self, id: u64) -> u8 {
        self.members.get(&id).map_or(0, |s| rank(*s))
    }

    /// Everything replicated in a CHAN record (members travel separately).
    pub(crate) fn same_meta(&self, other: &Channel) -> bool {
        self.modes == other.modes
            && self.key == other.key
            && self.limit == other.limit
            && self.params == other.params
            && self.bans == other.bans
            && self.excepts == other.excepts
            && self.invex == other.invex
            && self.topic == other.topic
            && self.topic_by == other.topic_by
    }

    /// Parameterless modes, e.g. `imnt`.
    pub(crate) fn flags(&self) -> String {
        self.modes.iter().collect()
    }

    pub(crate) fn set_flags(&mut self, flags: &str) {
        self.modes = flags.chars().collect();
    }

    /// `L#over j3:10` for CHAN records.
    pub(crate) fn param_text(&self) -> String {
        let params: Vec<_> = self.params.iter().map(|(m, v)| format!("{m}{v}")).collect();
        params.join(" ")
    }

    pub(crate) fn list(&self, mode: char) -> &Vec<String> {
        match mode {
            'e' => &self.excepts,
            'I' => &self.invex,
            _ => &self.bans,
        }
    }

    fn list_mut(&mut self, mode: char) -> &mut Vec<String> {
        match mode {
            'e' => &mut self.excepts,
            'I' => &mut self.invex,
            _ => &mut self.bans,
        }
    }

    /// `+flags[k][l][params] [key] [limit] [params]` for RPL_CHANNELMODEIS; the key
    /// only for members.
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
        for (mode, value) in &self.params {
            modes.push(*mode);
            args.push_str(&format!(" {value}"));
        }
        modes + &args
    }

    /// The +f rules in force: +f, or else the +F profile.
    pub(crate) fn flood_spec(&self) -> Option<modes::FloodSpec> {
        self.params
            .get(&'f')
            .map(String::as_str)
            .or_else(|| self.params.get(&'F').and_then(|p| modes::flood_profile(p)))
            .and_then(modes::parse_flood)
    }

    /// Members who see `id` join, part and quit: everyone, or while a delayed-join
    /// (+D) member is hidden, only that member and the channel operators.
    pub(crate) fn audience(&self, id: u64) -> Vec<u64> {
        let hidden = self.members.get(&id).is_some_and(|s| s & HIDDEN != 0);
        self.members
            .iter()
            .filter(|(m, s)| !hidden || **m == id || rank(**s) >= 3)
            .map(|(m, _)| *m)
            .collect()
    }
}

/// NAMES/WHO prefix for member status; only the highest unless multi-prefix.
pub(crate) fn status_prefix(status: u8, multi: bool) -> String {
    let mut prefixes = STATUSES
        .iter()
        .filter(|(bit, ..)| status & bit != 0)
        .map(|(.., prefix)| *prefix);
    if multi {
        prefixes.collect()
    } else {
        prefixes.next().map(String::from).unwrap_or_default()
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

/// Whether a +L or ~forward target is acceptable for channel `key`.
fn redirect_valid(target: &str, key: &str) -> bool {
    target.starts_with('#') && channel_valid(target) && fold(target) != key
}

impl Server {
    /// Secret and private channels are hidden from everyone but their members.
    pub(crate) fn visible(&self, ch: &Channel, id: u64) -> bool {
        !(ch.has('s') || ch.has('p')) || ch.members.contains_key(&id)
    }

    /// Whether `id` is selected by a `nick!user@host` mask or a matcher extban.
    pub(crate) fn matcher_hits(&self, id: u64, matcher: &str) -> bool {
        let c = &self.clients[&id];
        let Some((name, value)) = matcher.strip_prefix('~').and_then(|m| m.split_once(':')) else {
            // A vhost or cloak hides the real host from others, not from bans on it.
            let mask = fold(matcher);
            return [
                c.prefix(),
                format!("{}!~{}@{}", c.nick, c.user, shown_host(&c.host)),
                format!("{}!~{}@{}", c.nick, c.user, c.masked_host),
            ]
            .iter()
            .any(|identity| oper::matches(&mask, &fold(identity)));
        };
        match name {
            "account" if value == "0" => c.account.is_empty(),
            "account" => !c.account.is_empty() && oper::matches(&fold(value), &fold(&c.account)),
            "channel" => {
                let chan = value.trim_start_matches(['~', '&', '@', '%', '+']);
                let need = value
                    .chars()
                    .next()
                    .and_then(|p| STATUSES.iter().position(|(.., s)| *s == p))
                    .filter(|_| chan.len() < value.len())
                    .map_or(0, |i| 5 - i as u8);
                self.channels
                    .get(&fold(chan))
                    .and_then(|ch| ch.members.get(&id))
                    .is_some_and(|s| rank(*s) >= need)
            }
            "operclass" => c.oper.is_some_and(|o| oper::matches(value, o.name())),
            // `_` stands for a space, as masks cannot contain one.
            "realname" => oper::matches(&fold(&value.replace('_', "?")), &fold(&c.real)),
            "securitygroup" => {
                let (known, tls) = (c.known(), c.umodes.contains(&'z'));
                match value {
                    "known-users" => known,
                    "unknown-users" => !known,
                    "tls-users" => tls,
                    _ => known && tls,
                }
            }
            _ => false,
        }
    }

    /// Whether a list entry applies to `id` for `check`: plain masks and matchers
    /// stop everything, `~quiet` only speaking, `~nickchange` nick changes, and
    /// `~join`/`~forward` joins.
    fn entry_hits(&self, id: u64, entry: &str, check: Check) -> bool {
        let Some((name, value)) = entry.strip_prefix('~').and_then(|e| e.split_once(':')) else {
            return self.matcher_hits(id, entry);
        };
        let who = |value: &str| self.matcher_hits(id, value);
        match name {
            "time" => value
                .split_once(':')
                .is_some_and(|(_, inner)| self.entry_hits(id, inner, check)),
            "quiet" => check == Check::Speak && who(value),
            "nickchange" => check == Check::Nick && who(value),
            "join" => check == Check::Join && who(value),
            "forward" => check == Check::Join && value.split_once(':').is_some_and(|(_, w)| who(w)),
            "text" | "msgbypass" | "partmsg" => false,
            _ => who(entry),
        }
    }

    pub(crate) fn hits(&self, list: &[String], id: u64, check: Check) -> bool {
        list.iter().any(|entry| self.entry_hits(id, entry, check))
    }

    /// Banned for `check` and not excepted (+e).
    pub(crate) fn banned(&self, ch: &Channel, id: u64, check: Check) -> bool {
        self.hits(&ch.bans, id, check) && !self.hits(&ch.excepts, id, check)
    }

    /// The channel a matching `~forward` ban sends `id` to.
    fn forward_target(&self, ch: &Channel, id: u64) -> Option<String> {
        ch.bans.iter().find_map(|entry| {
            let (chan, who) = entry.strip_prefix("~forward:")?.split_once(':')?;
            self.matcher_hits(id, who).then(|| chan.to_string())
        })
    }

    /// Whether a `~msgbypass:<what>:` exception lets `id` past a message restriction.
    pub(crate) fn bypass(&self, ch: &Channel, id: u64, what: &str) -> bool {
        ch.excepts.iter().any(|entry| {
            entry
                .strip_prefix("~msgbypass:")
                .and_then(|v| v.split_once(':'))
                .is_some_and(|(w, who)| w == what && self.matcher_hits(id, who))
        })
    }

    /// Whether a `~partmsg` ban hides `id`'s part messages.
    pub(crate) fn hides_part(&self, ch: &Channel, id: u64) -> bool {
        ch.bans.iter().any(|entry| {
            entry
                .strip_prefix("~partmsg:")
                .is_some_and(|who| self.matcher_hits(id, who))
        })
    }

    /// Checks and rewrites a channel message from `id`: Err is the reason it is
    /// refused. Covers +n, +m, +M, bans, +T, +C, +c, +S, ~text and +G.
    pub(crate) fn channel_text(
        &self,
        id: u64,
        ch: &Channel,
        notice: bool,
        text: &str,
    ) -> Result<String, &'static str> {
        if self.privileged(id) {
            return Ok(text.into());
        }
        let status = ch.members.get(&id).copied();
        let rank = status.map_or(0, rank);
        // Operators are exempt from the content restrictions, not from +S or +G.
        let exempt = rank >= 3;
        let bypass = |what| self.bypass(ch, id, what);
        if ch.has('n') && status.is_none() && !bypass("external") {
            return Err("No external channel messages (+n)");
        }
        if ch.has('m') && rank == 0 && !bypass("moderated") {
            return Err("You need voice (+m)");
        }
        if ch.has('M') && rank == 0 && !self.clients[&id].known() && !bypass("moderated") {
            return Err("You need a registered nick to speak (+M)");
        }
        if rank == 0 && self.banned(ch, id, Check::Speak) {
            return Err("You are banned");
        }
        if ch.has('T') && notice && !exempt && !bypass("notice") {
            return Err("Notices are not permitted (+T)");
        }
        if ch.has('C') && modes::is_ctcp(text) && !exempt && !bypass("ctcp") {
            return Err("CTCPs are not permitted (+C)");
        }
        if ch.has('c') && modes::has_color(text) && !exempt && !bypass("color") {
            return Err("Colors are not permitted (+c)");
        }
        let mut text = if ch.has('S') {
            modes::strip_formatting(text)
        } else {
            text.to_string()
        };
        for (how, pattern) in ch
            .bans
            .iter()
            .filter_map(|e| e.strip_prefix("~text:")?.split_once(':'))
        {
            if exempt || self.hits(&ch.excepts, id, Check::Speak) {
                break;
            }
            if how == "block" && oper::matches(&fold(pattern), &fold(&text)) {
                return Err("Message blocked by a text ban");
            }
            if how == "censor" {
                text = modes::censor(&text, &[pattern.to_lowercase()]);
            }
        }
        if ch.has('G') && !bypass("censor") {
            text = modes::censor(&text, &self.config.badwords);
        }
        Ok(text)
    }

    /// Joins one channel; `forced` (SAJOIN, services) skips every restriction.
    pub(crate) fn join_channel(&mut self, id: u64, name: &str, key: Option<&str>, forced: bool) {
        self.join_hop(id, name, key, forced, 0);
    }

    /// `hops` counts +L and ~forward redirects, so a loop of them ends.
    fn join_hop(&mut self, id: u64, name: &str, key: Option<&str>, forced: bool, hops: u8) {
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
            let c = &self.clients[&id];
            // An invitation overrides +i, +b and +l (Modern), but not a key; an
            // invite exception (+I) overrides +i only.
            let invited = c.invites.contains(&folded);
            let mut redirect = None;
            let error = if ch.has('O') && c.oper.is_none() {
                Some((520, "Cannot join channel (IRCops only)"))
            } else if ch.has('z') && !c.umodes.contains(&'z') {
                Some((489, "Cannot join channel (SSL/TLS required)"))
            } else if ch.has('R') && !c.known() {
                Some((
                    477,
                    "Cannot join channel (+R): identify to a registered nick",
                ))
            } else if !ch.key.is_empty() && key != Some(ch.key.as_str()) {
                Some((475, "Cannot join channel (+k)"))
            } else if self.throttled(ch, &folded, id) {
                Some((
                    500,
                    "Too many join requests. Please wait a while and try again",
                ))
            } else if invited {
                None
            } else if self.banned(ch, id, Check::Join) {
                redirect = self.forward_target(ch, id);
                Some((474, "Cannot join channel (+b)"))
            } else if ch.has('i') && !self.hits(&ch.invex, id, Check::Join) {
                Some((473, "Cannot join channel (+i)"))
            } else if ch.limit > 0 && ch.members.len() >= ch.limit {
                redirect = ch.params.get(&'L').cloned();
                Some((471, "Cannot join channel (+l)"))
            } else {
                None
            };
            if let Some((code, text)) = error {
                let chan = ch.name.clone();
                match redirect.filter(|_| hops < 2) {
                    Some(target) => {
                        self.numeric(
                            id,
                            470,
                            &format!(
                                "{chan} {target} :{text}, so you are being transferred to {target}"
                            ),
                        );
                        self.join_hop(id, &target, None, false, hops + 1);
                    }
                    None => self.numeric(id, code, &format!("{chan} :{text}")),
                }
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
        // Services set their own status, as they track it themselves. A permanent
        // (+P) channel gives no one operator status for finding it empty.
        let mut status = if ch.members.is_empty() && !ch.has('P') && !service {
            OP
        } else {
            0
        };
        if ch.has('D') && !service {
            status |= HIDDEN;
        }
        ch.members.insert(id, status);
        let ch = &self.channels[&folded];
        self.broadcast(
            ch.audience(id),
            &format!(":{} JOIN {}", self.clients[&id].prefix(), ch.name),
        );
        if !ch.topic.is_empty() {
            self.topic_reply(id, &folded);
        }
        self.names(id, &folded, &ch.name);
        self.replay_history(id, &folded);
        self.note_join(&folded, id);
        self.auto_modes(&folded);
    }

    /// +j: whether `id` joined this channel too often lately.
    fn throttled(&self, ch: &Channel, key: &str, id: u64) -> bool {
        let Some((joins, seconds)) = ch.params.get(&'j').and_then(|v| modes::parse_throttle(v))
        else {
            return false;
        };
        self.joins
            .get(&(key.to_string(), id))
            .is_some_and(|(start, n)| start.elapsed().as_secs() < seconds && *n >= joins)
    }

    /// Counts a join for +j and for +f's join flood.
    fn note_join(&mut self, key: &str, id: u64) {
        let Some(ch) = self.channels.get(key) else {
            return;
        };
        if let Some((_, seconds)) = ch.params.get(&'j').and_then(|v| modes::parse_throttle(v)) {
            let entry = self
                .joins
                .entry((key.to_string(), id))
                .or_insert((Instant::now(), 0));
            if entry.0.elapsed().as_secs() >= seconds {
                *entry = (Instant::now(), 0);
            }
            entry.1 += 1;
        }
        self.flood_event(key, 'j', id, "");
    }

    /// Counts an event for +f/+F; when a rule breaks, applies its action. True when
    /// the event's message should be dropped: its sender was kicked, or the channel
    /// was just moderated because of it.
    pub(crate) fn flood_event(&mut self, key: &str, kind: char, id: u64, text: &str) -> bool {
        let Some(ch) = self.channels.get(key) else {
            return false;
        };
        // Halfops and above, operators with override and services are exempt.
        if ch.rank(id) >= 2 || self.privileged(id) {
            return false;
        }
        let Some(spec) = ch.flood_spec() else {
            return false;
        };
        let name = ch.name.clone();
        let Some(rule) = self
            .floods
            .entry(key.into())
            .or_default()
            .hit(&spec, kind, id, text)
        else {
            return false;
        };
        let what = match kind {
            'c' => "CTCP",
            'j' => "join",
            'k' => "knock",
            'm' => "message",
            'n' => "nick",
            't' => "text",
            _ => "repeat",
        };
        let limit = format!("limit is {} per {} seconds", rule.count, spec.seconds);
        let expires = |minutes: u32| timestamp() + u64::from(minutes) * 60;
        if matches!(kind, 't' | 'r') {
            if rule.action == 'b' {
                let mask = format!("*!*@{}", self.clients[&id].shown());
                if self.server_mode(key, true, 'b', Some(mask.clone())) && rule.minutes > 0 {
                    self.timed.push(Timed {
                        at: expires(rule.minutes),
                        key: key.into(),
                        mode: 'b',
                        param: Some(mask),
                    });
                }
            }
            self.server_kick(key, id, &format!("Flooding ({what} {limit})"));
            return true;
        }
        if !self.channels[key].has(rule.action) {
            let notice = format!(
                ":{} NOTICE {name} :*** Channel {what} flood detected ({limit}), setting mode +{}",
                self.config.name, rule.action
            );
            self.broadcast(self.channels[key].members.keys().copied(), &notice);
            self.server_mode(key, true, rule.action, None);
            if rule.minutes > 0 {
                self.timed.push(Timed {
                    at: expires(rule.minutes),
                    key: key.into(),
                    mode: rule.action,
                    param: None,
                });
            }
        }
        matches!(kind, 'm' | 'c')
    }

    /// A mode change made by this server (flood actions, timers, +Z, +d), shown to the
    /// channel. Handles flags and list entries; true if anything changed.
    pub(crate) fn server_mode(
        &mut self,
        key: &str,
        adding: bool,
        mode: char,
        param: Option<String>,
    ) -> bool {
        let Some(ch) = self.channels.get_mut(key) else {
            return false;
        };
        let changed = match &param {
            Some(entry) if "beI".contains(mode) => {
                let list = ch.list_mut(mode);
                let before = list.len();
                if !adding {
                    list.retain(|e| fold(e) != fold(entry));
                } else if before < MAX_BANS && !list.iter().any(|e| fold(e) == fold(entry)) {
                    list.push(entry.clone());
                }
                list.len() != before
            }
            _ if adding => ch.modes.insert(mode),
            _ => ch.modes.remove(&mode),
        };
        if changed {
            let sign = if adding { '+' } else { '-' };
            let arg = param.map(|p| format!(" {p}")).unwrap_or_default();
            let ch = &self.channels[key];
            self.broadcast(
                ch.members.keys().copied(),
                &format!(":{} MODE {} {sign}{mode}{arg}", self.config.name, ch.name),
            );
        }
        changed
    }

    /// A kick by this server (flood protection).
    pub(crate) fn server_kick(&mut self, key: &str, target: u64, reason: &str) {
        let Some(ch) = self.channels.get(key) else {
            return;
        };
        let line = format!(
            ":{} KICK {} {} :{reason}",
            self.config.name, ch.name, self.clients[&target].nick
        );
        self.broadcast(ch.audience(target), &line);
        self.remove_member(target, key);
        self.kicked.insert((key.into(), target), reason.into());
        self.auto_modes(key);
    }

    /// Keeps the server's own modes right: +Z while every member of a +z channel uses
    /// TLS, and +d while +D is off but members it hid are still hidden.
    pub(crate) fn auto_modes(&mut self, key: &str) {
        let Some(ch) = self.channels.get(key) else {
            return;
        };
        let secure = ch.has('z')
            && ch
                .members
                .keys()
                .all(|m| self.clients[m].umodes.contains(&'z'));
        let hidden = !ch.has('D') && ch.members.values().any(|s| s & HIDDEN != 0);
        for (mode, wanted) in [('Z', secure), ('d', hidden)] {
            if self.channels[key].has(mode) != wanted {
                self.server_mode(key, wanted, mode, None);
            }
        }
    }

    /// Shows a hidden (+D) member to the rest of the channel, when it speaks or is
    /// given a status.
    pub(crate) fn reveal(&mut self, key: &str, id: u64) {
        let Some(ch) = self.channels.get(key) else {
            return;
        };
        if ch.members.get(&id).is_none_or(|s| s & HIDDEN == 0) {
            return;
        }
        let saw = ch.audience(id);
        *self
            .channels
            .get_mut(key)
            .unwrap()
            .members
            .get_mut(&id)
            .unwrap() &= !HIDDEN;
        let ch = &self.channels[key];
        let others: Vec<_> = ch
            .members
            .keys()
            .copied()
            .filter(|m| !saw.contains(m))
            .collect();
        self.broadcast(
            others,
            &format!(":{} JOIN {}", self.clients[&id].prefix(), ch.name),
        );
        self.auto_modes(key);
    }

    /// Keeps a line for +H.
    pub(crate) fn remember(&mut self, key: &str, at: u64, line: String) {
        let Some((lines, _)) = self
            .channels
            .get(key)
            .and_then(|ch| ch.params.get(&'H'))
            .and_then(|v| modes::parse_history(v))
        else {
            return;
        };
        let history = self.history.entry(key.into()).or_default();
        history.push_back((at, line));
        while history.len() > lines {
            history.pop_front();
        }
    }

    /// Plays +H history to a user who just joined.
    fn replay_history(&self, id: u64, key: &str) {
        let Some((_, seconds)) = self.channels[key]
            .params
            .get(&'H')
            .and_then(|v| modes::parse_history(v))
        else {
            return;
        };
        let since = timestamp().saturating_sub(seconds);
        for (_, line) in self
            .history
            .get(key)
            .into_iter()
            .flatten()
            .filter(|(at, _)| *at >= since)
        {
            self.send(id, line);
        }
    }

    /// Drops what this server keeps about a channel that ended.
    pub(crate) fn forget_channel(&mut self, key: &str) {
        self.floods.remove(key);
        self.history.remove(key);
        self.joins.retain(|(k, _), _| k != key);
        self.timed.retain(|t| t.key != key);
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
            let privileged = self.privileged(id);
            if !ch.members.contains_key(&id) && !privileged {
                self.numeric(id, 442, &format!("{} :You're not on that channel", p[1]));
                return;
            }
            if ch.has('V') && !privileged {
                self.numeric(
                    id,
                    518,
                    &format!(":Cannot invite (+V) at channel {}", ch.name),
                );
                return;
            }
            if ch.has('i') && ch.rank(id) < 2 && !privileged {
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

    /// KNOCK asks the operators of an invite-only channel for an invitation.
    pub(crate) fn knock(&mut self, id: u64, p: &[String]) {
        let key = fold(&p[0]);
        let Some(ch) = self.channels.get(&key) else {
            self.numeric(id, 403, &format!("{} :No such channel", p[0]));
            return;
        };
        let refusal = if ch.members.contains_key(&id) {
            Some("You're already there!")
        } else if !ch.has('i') {
            Some("Channel is not invite only!")
        } else if ch.has('K') {
            Some("No knocks are allowed! (+K)")
        } else if self.banned(ch, id, Check::Join) {
            Some("You're banned!")
        } else {
            None
        };
        if let Some(why) = refusal {
            self.numeric(id, 480, &format!(":Cannot knock on {} ({why})", ch.name));
            return;
        }
        let reason = p
            .get(1)
            .filter(|r| !r.is_empty())
            .map_or("no reason specified", |r| truncate(r, 200));
        let c = &self.clients[&id];
        let line = format!(
            ":{} NOTICE @{} :[Knock] by {} ({reason})",
            self.config.name,
            ch.name,
            c.prefix()
        );
        let ops: Vec<_> = ch
            .members
            .iter()
            .filter(|(_, s)| rank(**s) >= 2)
            .map(|(m, _)| *m)
            .collect();
        self.broadcast(ops, &line);
        self.send(
            id,
            &format!(
                ":{} NOTICE {} :Knocked on {}",
                self.config.name, c.nick, ch.name
            ),
        );
        self.flood_event(&key, 'k', id, "");
    }

    pub(crate) fn kick(&mut self, id: u64, p: &[String]) {
        let key = fold(&p[0]);
        let Some(ch) = self.channels.get(&key) else {
            self.numeric(id, 403, &format!("{} :No such channel", p[0]));
            return;
        };
        let privileged = self.privileged(id);
        if !ch.members.contains_key(&id) && !privileged {
            self.numeric(id, 442, &format!("{} :You're not on that channel", p[0]));
            return;
        }
        let rank = ch.rank(id);
        if rank < 2 && !privileged {
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
            // Only services kick a +q user; +Q stops kicks; halfops kick only voiced
            // and regular users, and no one kicks a higher status.
            let target = ch.rank(other);
            let refusal = if self.clients[&other].umodes.contains(&'q')
                && !self.is_service(id)
                && other != id
            {
                Some((972, format!("KICK :{nick} is unkickable (+q)")))
            } else if privileged || other == id {
                None
            } else if ch.has('Q') {
                Some((
                    972,
                    format!("KICK :Kicks are not allowed in {} (+Q)", ch.name),
                ))
            } else if target > rank || (rank == 2 && target >= 2) {
                Some((
                    482,
                    format!(
                        "{} :You cannot kick {nick}, who has a higher status",
                        ch.name
                    ),
                ))
            } else {
                None
            };
            if let Some((code, text)) = refusal {
                self.numeric(id, code, &text);
                continue;
            }
            let reason = p
                .get(2)
                .filter(|r| !r.is_empty())
                .unwrap_or(&self.clients[&id].nick)
                .clone();
            let mut recipients = ch.audience(other);
            if ch.members.contains_key(&id) && !recipients.contains(&id) {
                recipients.push(id);
            }
            self.broadcast(
                recipients,
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
        self.auto_modes(&key);
    }

    fn list_reply(&self, id: u64, key: &str, mode: char) {
        let ch = &self.channels[key];
        let (item, end, what) = match mode {
            'e' => (348, 349, "exception"),
            'I' => (346, 347, "invite exception"),
            _ => (367, 368, "ban"),
        };
        for entry in ch.list(mode) {
            self.numeric(id, item, &format!("{} {entry}", ch.name));
        }
        self.numeric(id, end, &format!("{} :End of channel {what} list", ch.name));
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
        let name = ch.name.clone();
        let (privileged, service) = (self.privileged(id), self.is_service(id));
        let oper = self.clients[&id].oper.is_some();
        let rank = ch.rank(id);
        let (mut adding, mut arg, mut denied) = (true, 2, None);
        let (mut modes, mut args, mut revealed) = (String::new(), Vec::new(), Vec::new());
        for mode in p[1].chars() {
            match mode {
                '+' => adding = true,
                '-' => adding = false,
                _ => {}
            }
            if matches!(mode, '+' | '-') {
                continue;
            }
            // CHANMODES=beI,k,fFHjLl,flags: lists, k and statuses always take a
            // parameter; l and fFHjL only when set.
            let param = if "beIkqaohv".contains(mode) || (adding && "lfFHjL".contains(mode)) {
                let value = p.get(arg).cloned();
                arg += usize::from(value.is_some());
                value
            } else {
                None
            };
            if !modes::CHAN_MODES.contains(mode) {
                self.numeric(id, 472, &format!("{mode} :is unknown mode char to me"));
                continue;
            }
            if "beI".contains(mode) && param.is_none() {
                self.list_reply(id, &key, mode);
                continue;
            }
            let needed = match mode {
                'q' | 'a' => 5,
                'o' | 'h' | 'k' | 'l' | 'p' | 's' | 'z' | 'D' | 'Q' | 'R' => 3,
                m if modes::CHAN_PARAMS.contains(m) => 3,
                _ => 2,
            };
            let allowed = match mode {
                'r' => service,
                'Z' | 'd' => false,
                'O' | 'P' => privileged || (oper && rank >= 3),
                _ => privileged || rank >= needed,
            };
            if !allowed {
                denied = Some(match mode {
                    'q' | 'a' => (499, format!("{name} :You're not a channel owner")),
                    'O' | 'P' if !oper => {
                        (481, ":Permission Denied- You're not an IRC operator".into())
                    }
                    _ => (482, format!("{name} :You're not channel operator")),
                });
                continue;
            }
            if param.is_none() && ("qaohv".contains(mode) || (adding && "lfFHjL".contains(mode))) {
                self.numeric(id, 461, "MODE :Not enough parameters");
                continue;
            }
            let target = match (mode, &param) {
                ('q' | 'a' | 'o' | 'h' | 'v', Some(nick)) => match self.find_nick(nick) {
                    Some(target) => Some((target, self.clients[&target].nick.clone())),
                    None => {
                        self.numeric(id, 401, &format!("{nick} :No such nick"));
                        continue;
                    }
                },
                _ => None,
            };
            // Anyone may drop their own status; no one takes a higher one's.
            if target.as_ref().is_some_and(|(t, _)| {
                !adding && !privileged && *t != id && self.channels[&key].rank(*t) > rank
            }) {
                denied = Some((482, format!("{name} :You're not channel operator")));
                continue;
            }
            let ch = self.channels.get_mut(&key).unwrap();
            // Ok(Some(echo-param?)) when the mode changed, Ok(None) for a no-op.
            let outcome: Result<Option<Option<String>>, (u16, String)> = match mode {
                'k' if adding => match param {
                    Some(k) if key_valid(&k) => Ok((ch.key != k).then(|| {
                        ch.key = k.clone();
                        Some(k)
                    })),
                    // An empty or missing key is invalid too; the parameter shows as `*`.
                    _ => Err((696, format!("{name} k * :Invalid key"))),
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
                                "{name} l {} :Invalid limit",
                                if value.is_empty() { "*" } else { &value }
                            ),
                        )),
                    }
                }
                'l' => Ok((ch.limit != 0).then(|| {
                    ch.limit = 0;
                    None
                })),
                'f' | 'F' | 'H' | 'j' | 'L' if adding => {
                    let value = param.unwrap();
                    let valid = value.len() <= 100
                        && match mode {
                            'f' => modes::parse_flood(&value).is_some(),
                            'F' => modes::flood_profile(&value).is_some(),
                            'H' => modes::parse_history(&value).is_some(),
                            'j' => modes::parse_throttle(&value).is_some(),
                            _ => redirect_valid(&value, &key),
                        };
                    if valid {
                        Ok((ch.params.get(&mode) != Some(&value)).then(|| {
                            ch.params.insert(mode, value.clone());
                            Some(value)
                        }))
                    } else {
                        let shown = if value.is_empty() { "*" } else { &value };
                        Err((696, format!("{name} {mode} {shown} :Invalid parameter")))
                    }
                }
                'f' | 'F' | 'H' | 'j' | 'L' => Ok(ch.params.remove(&mode).map(|_| None)),
                'b' | 'e' | 'I' => {
                    let raw = truncate(param.as_deref().unwrap(), 100);
                    match modes::list_entry(raw, mode) {
                        None => Err((696, format!("{name} {mode} {raw} :Invalid ban mask"))),
                        Some(entry) => {
                            let folded = fold(&entry);
                            let list = ch.list_mut(mode);
                            if adding {
                                if list.iter().any(|b| fold(b) == folded) {
                                    Ok(None)
                                } else if list.len() >= MAX_BANS {
                                    Err((478, format!("{name} {entry} :Channel list is full")))
                                } else {
                                    list.push(entry.clone());
                                    if let Some(minutes) = modes::entry_minutes(&entry) {
                                        self.timed.push(Timed {
                                            at: timestamp() + minutes * 60,
                                            key: key.clone(),
                                            mode,
                                            param: Some(entry.clone()),
                                        });
                                    }
                                    Ok(Some(Some(entry)))
                                }
                            } else {
                                // Unsetting matches case-insensitively, as clients may retype it.
                                let before = list.len();
                                list.retain(|b| fold(b) != folded);
                                Ok((list.len() < before).then_some(Some(entry)))
                            }
                        }
                    }
                }
                'q' | 'a' | 'o' | 'h' | 'v' => {
                    let (target, nick) = target.unwrap();
                    let bit = STATUSES.iter().find(|(_, m, _)| *m == mode).unwrap().0;
                    match ch.members.get_mut(&target) {
                        Some(status) => {
                            if adding && *status & HIDDEN != 0 {
                                revealed.push(target);
                            }
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
                        None => Err((441, format!("{nick} {name} :They aren't on that channel"))),
                    }
                }
                _ => Ok((ch.modes.contains(&mode) != adding).then(|| {
                    if adding {
                        ch.modes.insert(mode);
                    } else {
                        ch.modes.remove(&mode);
                    }
                    None
                })),
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
        if let Some((code, text)) = denied {
            self.numeric(id, code, &text);
        }
        for target in revealed {
            self.reveal(&key, target);
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
        if !self.channels[&key].params.contains_key(&'H') {
            self.history.remove(&key);
        }
        self.auto_modes(&key);
        // A local channel kept only by +P ends with -P (network channels end in
        // sync_channels, after peers hear of it).
        if key.starts_with('&')
            && self.channels[&key].members.is_empty()
            && !self.channels[&key].has('P')
        {
            self.channels.remove(&key);
            self.forget_channel(&key);
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
        assert_eq!(status_prefix(VOICE | HIDDEN, false), "+");
        assert_eq!(status_prefix(OWNER | HALFOP, true), "~%");
        assert_eq!((rank(OWNER | VOICE), rank(HALFOP), rank(HIDDEN)), (5, 2, 0));
        let mut ch = Channel::new("#c", 1, 1, "s".into());
        ch.set_flags("is");
        assert_eq!(ch.flags(), "is");
        ch.key = "k".into();
        ch.limit = 5;
        ch.params.insert('j', "3:10".into());
        ch.params.insert('L', "#over".into());
        assert_eq!(ch.mode_reply(true), "+isklLj k 5 #over 3:10");
        assert_eq!(ch.mode_reply(false), "+isklLj * 5 #over 3:10");
        assert_eq!(ch.param_text(), "L#over j3:10");
        ch.members.insert(1, HIDDEN);
        ch.members.insert(2, OP);
        ch.members.insert(3, VOICE);
        assert_eq!(ch.audience(1), [1, 2]);
        assert_eq!(ch.audience(3), [1, 2, 3]);
        assert!(redirect_valid("#b", "#a") && !redirect_valid("#A", "#a"));
    }
}
