//! Server bans: KLINE (this server) and GLINE (network-wide, also used by
//! services' AKILL). Masks match `nick!user@host`, with or without the `~` that
//! marks usernames, and bans can expire.
use super::*;
use network::{decode, encode};

const MAX_SERVER_BANS: usize = 1000;

#[derive(Clone)]
pub(crate) struct ServerBan {
    /// Normalized `nick!user@host` mask.
    mask: String,
    reason: String,
    setter: String,
    /// Unix time the ban ends; 0 means never.
    expires: u64,
    global: bool,
}

impl ServerBan {
    fn active(&self, now: u64) -> bool {
        self.expires == 0 || now < self.expires
    }
}

/// Completes `user@host` or a bare host to `nick!user@host`. Refuses masks with
/// spaces or commas, and masks of only wildcards, which would ban everyone.
pub(crate) fn ban_mask(raw: &str) -> Option<String> {
    let mask = match (raw.contains('!'), raw.contains('@')) {
        (true, true) => raw.to_string(),
        (false, true) => format!("*!{raw}"),
        (true, false) => format!("{raw}@*"),
        (false, false) => format!("*!*@{raw}"),
    };
    let specific = mask.chars().any(|c| !"*?.:!@~".contains(c));
    (specific && mask.len() <= 120 && !mask.contains([' ', ','])).then_some(mask)
}

impl Server {
    /// The active ban, if any, matching a client.
    pub(crate) fn server_ban_for(&self, id: u64) -> Option<&ServerBan> {
        let c = &self.clients[&id];
        let host = shown_host(&c.host);
        let identities = [
            fold(&format!("{}!{}@{host}", c.nick, c.user)),
            fold(&format!("{}!~{}@{host}", c.nick, c.user)),
        ];
        let now = timestamp();
        self.server_bans.iter().find(|ban| {
            ban.active(now)
                && identities
                    .iter()
                    .any(|identity| oper::matches(&fold(&ban.mask), identity))
        })
    }

    /// Disconnects a banned local user; true if it was banned.
    pub(crate) fn reject_banned(&mut self, id: u64) -> bool {
        let Some(reason) = self.server_ban_for(id).map(|b| b.reason.clone()) else {
            return false;
        };
        self.numeric(
            id,
            465,
            &format!(":You are banned from this server: {reason}"),
        );
        self.send(id, &format!("ERROR :Closing Link: Banned ({reason})"));
        self.disconnect(id, &format!("Banned ({reason})"));
        true
    }

    /// Adds or replaces a ban and disconnects matching local users. False if full.
    pub(crate) fn add_server_ban(
        &mut self,
        mask: String,
        seconds: u64,
        reason: &str,
        setter: &str,
        global: bool,
    ) -> bool {
        let expires = if seconds == 0 {
            0
        } else {
            timestamp() + seconds
        };
        let ban = ServerBan {
            reason: truncate(reason, 200).into(),
            setter: setter.into(),
            expires,
            global,
            mask,
        };
        self.server_bans
            .retain(|b| !(b.global == global && fold(&b.mask) == fold(&ban.mask)));
        if self.server_bans.len() >= MAX_SERVER_BANS {
            return false;
        }
        self.server_bans.push(ban);
        let local: Vec<_> = self
            .clients
            .iter()
            .filter(|(_, c)| c.route.is_none() && c.registered)
            .map(|(&id, _)| id)
            .collect();
        for id in local {
            self.reject_banned(id);
        }
        true
    }

    pub(crate) fn remove_server_ban(&mut self, mask: &str, global: bool) -> bool {
        let before = self.server_bans.len();
        self.server_bans
            .retain(|b| !(b.global == global && fold(&b.mask) == fold(mask)));
        self.server_bans.len() < before
    }

    pub(crate) fn gline_record(&self, ban: &ServerBan) -> String {
        format!(
            "GLINE {} {} {} {}",
            encode(&ban.mask),
            ban.expires,
            encode(&ban.setter),
            encode(&ban.reason)
        )
    }

    /// Network-wide bans, for a new link's burst.
    pub(crate) fn gline_records(&self) -> Vec<String> {
        let now = timestamp();
        self.server_bans
            .iter()
            .filter(|b| b.global && b.active(now))
            .map(|b| self.gline_record(b))
            .collect()
    }

    /// Applies a GLINE or UNGLINE frame from a peer; None for a malformed one.
    pub(crate) fn gline_frame(&mut self, p: &[&str]) -> Option<()> {
        let mask = ban_mask(&decode(p[1])?)?;
        if p[0] == "UNGLINE" {
            self.remove_server_ban(&mask, true);
            return Some(());
        }
        let expires: u64 = p[2].parse().ok()?;
        let (setter, reason) = (decode(p[3])?, decode(p[4])?);
        let now = timestamp();
        if expires != 0 && expires <= now {
            return Some(());
        }
        let seconds = if expires == 0 { 0 } else { expires - now };
        self.add_server_ban(mask, seconds, &reason, &setter, true);
        Some(())
    }

    /// KLINE/GLINE `<mask> <seconds> :<reason>` adds; `<mask>` alone removes.
    pub(crate) fn ban_command(&mut self, id: u64, command: &str, p: &[String]) {
        let global = command == "GLINE";
        let kind = if global { "G-Line" } else { "K-Line" };
        let notice = |server: &Self, text: String| {
            let nick = &server.clients[&id].nick;
            server.send(
                id,
                &format!(":{} NOTICE {nick} :{text}", server.config.name),
            );
        };
        let Some(mask) = ban_mask(&p[0]) else {
            notice(self, format!("Invalid or too broad {kind} mask: {}", p[0]));
            return;
        };
        if p.len() == 1 {
            if self.remove_server_ban(&mask, global) {
                if global {
                    self.net_flood(None, &format!("UNGLINE {}", encode(&mask)));
                }
                notice(self, format!("{kind} removed for {mask}"));
                let by = self.clients[&id].nick.clone();
                self.sno('G', &format!("{kind} removed for {mask} by {by}"));
            } else {
                notice(self, format!("No {kind} for {mask}"));
            }
            return;
        }
        let (Some(seconds), Some(reason)) = (p[1].parse::<u64>().ok(), p.get(2)) else {
            self.numeric(id, 461, &format!("{command} :Not enough parameters"));
            return;
        };
        let setter = self.clients[&id].prefix();
        // Announce before enforcing, in case the ban removes the operator who set it.
        notice(self, format!("{kind} added for {mask}"));
        self.sno(
            'G',
            &format!("{kind} added for {mask} by {setter}: {reason}"),
        );
        if !self.add_server_ban(mask.clone(), seconds, reason, &setter, global) {
            notice(self, format!("The {kind} list is full"));
            return;
        }
        if global {
            let ban = self.server_bans.last().unwrap();
            self.net_flood(None, &self.gline_record(ban));
        }
    }

    /// STATS k / STATS g list bans to operators.
    pub(crate) fn stats(&self, id: u64, p: &[String]) {
        let letter = p.first().and_then(|s| s.chars().next()).unwrap_or('*');
        let global = match letter.to_ascii_lowercase() {
            'k' => Some(false),
            'g' => Some(true),
            _ => None,
        };
        if let Some(global) = global {
            if self.clients[&id].oper.is_none() {
                self.numeric(id, 481, ":Permission denied - You are not an IRC operator");
                return;
            }
            let now = timestamp();
            let (code, mark) = if global { (223, 'G') } else { (216, 'K') };
            for ban in self
                .server_bans
                .iter()
                .filter(|b| b.global == global && b.active(now))
            {
                let left = if ban.expires == 0 {
                    0
                } else {
                    ban.expires - now
                };
                self.numeric(
                    id,
                    code,
                    &format!("{mark} {} {left} {} :{}", ban.mask, ban.setter, ban.reason),
                );
            }
        }
        self.numeric(id, 219, &format!("{letter} :End of STATS report"));
    }

    pub(crate) fn prune_server_bans(&mut self) {
        let now = timestamp();
        self.server_bans.retain(|b| b.active(now));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks() {
        assert_eq!(ban_mask("*@192.0.2.1").as_deref(), Some("*!*@192.0.2.1"));
        assert_eq!(ban_mask("192.0.2.*").as_deref(), Some("*!*@192.0.2.*"));
        assert_eq!(ban_mask("bad!*@*").as_deref(), Some("bad!*@*"));
        assert_eq!(ban_mask("bad!user").as_deref(), Some("bad!user@*"));
        for broad in ["*@*", "*!*@*", "*", "*.*", "a b@c", "x,y@z"] {
            assert_eq!(ban_mask(broad), None, "{broad}");
        }
    }
}
