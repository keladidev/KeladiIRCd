use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperClass {
    Local,
    Global,
    Override,
}

impl OperClass {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "local" => Some(Self::Local),
            "global" => Some(Self::Global),
            "override" => Some(Self::Override),
            _ => None,
        }
    }
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Global => "global",
            Self::Override => "override",
        }
    }
}

#[derive(Clone)]
pub struct OperConfig {
    pub name: String,
    pub password: String,
    pub host: String,
    pub class: OperClass,
}

pub(crate) fn validate_config(config: &Config) -> io::Result<()> {
    let mut names = BTreeSet::new();
    for oper in &config.opers {
        if !nick_valid(&oper.name)
            || oper.password.is_empty()
            || oper.password.len() > 128
            || oper.password.contains(['\0', '\r', '\n'])
            || oper.host.is_empty()
            || !oper
                .host
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b".:*?".contains(&b))
            || !names.insert(&oper.name)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid or duplicate operator configuration",
            ));
        }
    }
    Ok(())
}

/// `*`/`?` wildcard match, used for operator host masks, bans and WHO.
pub(crate) fn matches(mask: &str, value: &str) -> bool {
    let (mut m, mut v, mut star, mut retry) = (0, 0, None, 0);
    let (mask, value) = (mask.as_bytes(), value.as_bytes());
    while v < value.len() {
        if m < mask.len() && (mask[m] == b'?' || mask[m] == value[v]) {
            m += 1;
            v += 1;
        } else if m < mask.len() && mask[m] == b'*' {
            star = Some(m);
            m += 1;
            retry = v;
        } else if let Some(s) = star {
            m = s + 1;
            retry += 1;
            v = retry;
        } else {
            return false;
        }
    }
    while m < mask.len() && mask[m] == b'*' {
        m += 1;
    }
    m == mask.len()
}

impl Server {
    pub(super) fn can_override(&self, id: u64) -> bool {
        self.clients
            .get(&id)
            .is_some_and(|c| c.oper == Some(OperClass::Override))
    }

    /// Override-class operators and services pass channel permission checks.
    pub(super) fn privileged(&self, id: u64) -> bool {
        self.can_override(id) || self.is_service(id)
    }

    /// Users and the server stand-in that belong to a directly linked services server.
    pub(super) fn is_service(&self, id: u64) -> bool {
        self.clients
            .get(&id)
            .and_then(|c| c.route)
            .is_some_and(|route| self.links.get(&route).is_some_and(|l| l.is_services()))
    }

    /// An action forced on a local user by an operator (SAJOIN/SAPART) or services
    /// (SVSNICK, login, +R). `source` is the prefix shown for mode changes.
    /// Joins bypass key, invite, ban and limit modes.
    pub(super) fn force(&mut self, target: u64, msg: &Message, source: &str) {
        let param = msg.params.first().map(String::as_str).unwrap_or("");
        match msg.command.as_str() {
            "JOIN" | "PART" => {
                for name in param.split(',') {
                    if msg.command == "JOIN" {
                        self.join_channel(target, name, None, true);
                    } else {
                        let nick = self.clients[&target].nick.clone();
                        self.part(target, name, &nick);
                    }
                }
            }
            "NICK" => {
                if nick_valid(param)
                    && param != self.clients[&target].nick
                    && self.find_nick(param).is_none_or(|other| other == target)
                {
                    self.change_nick(target, param);
                }
            }
            "ACCOUNT" => {
                let c = self.clients.get_mut(&target).unwrap();
                c.account = param.into();
                let c = &self.clients[&target];
                let identity = c.prefix();
                if param.is_empty() {
                    self.numeric(target, 901, &format!("{identity} :You are now logged out"));
                } else {
                    self.numeric(
                        target,
                        900,
                        &format!("{identity} {param} :You are now logged in as {param}"),
                    );
                }
            }
            "UMODE" => {
                let on = param == "+R";
                let c = self.clients.get_mut(&target).unwrap();
                if c.identified != on {
                    c.identified = on;
                    let line = format!(":{source} MODE {} :{param}", c.nick);
                    self.send(target, &line);
                }
            }
            _ => {}
        }
    }

    /// Kills a user anywhere on the network on behalf of `id` (an operator or services).
    pub(super) fn kill_user(&mut self, id: u64, target: u64, reason: &str) {
        let actor = &self.clients[&id];
        let (prefix, name) = if actor.server {
            (actor.home.clone(), actor.home.clone())
        } else {
            (actor.prefix(), actor.nick.clone())
        };
        let reason = format!("Killed by {name}: {}", truncate(reason, 200));
        self.send(
            target,
            &format!(":{prefix} KILL {} :{reason}", self.clients[&target].nick),
        );
        self.send(target, &format!("ERROR :{reason}"));
        let uid = self.clients[&target].uid.clone();
        self.remember_deleted(&uid);
        let remote = self.clients[&target].route.is_some();
        self.disconnect(target, &reason);
        if remote {
            self.net_flood(None, &format!("REMOVE {uid} {}", network::encode(&reason)));
        }
        eprintln!("KILL by {prefix}: {uid}");
    }

    pub(super) fn oper_login(&mut self, id: u64, p: &[String]) {
        // The password is checked before the host, so only someone who knows it learns
        // that the name exists; every failure counts towards closing the connection.
        let Some(oper) = self
            .config
            .opers
            .iter()
            .find(|o| o.name == p[0] && o.password == p[1])
        else {
            self.numeric(id, 464, ":Password incorrect");
            self.auth_failed(id);
            return;
        };
        if !matches(&oper.host, &self.clients[&id].host) {
            self.numeric(id, 491, ":No O-lines for your host");
            self.auth_failed(id);
            return;
        }
        self.clients.get_mut(&id).unwrap().oper = Some(oper.class);
        self.numeric(id, 381, ":You are now an IRC operator");
        let c = &self.clients[&id];
        self.send(id, &format!(":{} MODE {} :+o", c.prefix(), c.nick));
        eprintln!("OPER {} logged in from {}", p[0], c.host);
    }

    pub(super) fn oper_command(&mut self, id: u64, command: &str, p: &[String]) {
        let Some(class) = self.clients[&id].oper else {
            self.numeric(id, 481, ":Permission denied - You are not an IRC operator");
            return;
        };
        match command {
            "KILL" => {
                let Some(target) = self.find_nick(&p[0]) else {
                    self.numeric(id, 401, &format!("{} :No such nick", p[0]));
                    return;
                };
                if class == OperClass::Local && self.clients[&target].route.is_some() {
                    self.numeric(id, 481, ":Your operator class permits only local KILL");
                    return;
                }
                // The reason is optional, as Ergo and other servers accept.
                let reason = p.get(1).map_or("No reason given", String::as_str);
                self.kill_user(id, target, reason);
            }
            "WALLOPS" => {
                let recipients: Vec<_> = self
                    .clients
                    .iter()
                    .filter(|(_, c)| c.oper.is_some())
                    .map(|(&id, _)| id)
                    .collect();
                self.broadcast(
                    recipients,
                    &format!(":{} WALLOPS :{}", self.clients[&id].prefix(), p[0]),
                );
            }
            "SQUIT" | "CONNECT" => {
                if class == OperClass::Local {
                    self.numeric(id, 481, ":Global operator privileges required");
                    return;
                }
                if command == "CONNECT" {
                    // Re-enables a link after SQUIT. An incoming-only link is accepted
                    // again when the peer reconnects; an outgoing one is redialled.
                    let outgoing = match self.config.links.iter().find(|l| l.name == p[0]) {
                        Some(l) => l.address.is_some(),
                        None => {
                            self.numeric(id, 402, &format!("{} :No link configuration", p[0]));
                            return;
                        }
                    };
                    self.disabled_links.remove(&p[0]);
                    let text = if outgoing {
                        "Link connection enabled for"
                    } else {
                        "Incoming link accepted again from"
                    };
                    self.send(
                        id,
                        &format!(
                            ":{} NOTICE {} :{text} {}",
                            self.config.name, self.clients[&id].nick, p[0]
                        ),
                    );
                } else if let Some((&link, _)) = self.links.iter().find(|(_, l)| l.name == p[0]) {
                    self.disabled_links.insert(p[0].clone());
                    self.drop_link(
                        link,
                        p.get(1).map(String::as_str).unwrap_or("Operator SQUIT"),
                    );
                } else {
                    self.numeric(id, 402, &format!("{} :No directly connected server", p[0]));
                }
            }
            "SAJOIN" | "SAPART" => {
                if class != OperClass::Override {
                    self.numeric(id, 481, ":Channel override privileges required");
                    return;
                }
                let Some(target) = self.find_nick(&p[0]) else {
                    self.numeric(id, 401, &format!("{} :No such nick", p[0]));
                    return;
                };
                let action = format!(
                    "{} {}",
                    if command == "SAJOIN" { "JOIN" } else { "PART" },
                    p[1]
                );
                // FORCE peers accept exactly one parameter; reject anything else here.
                let Some(msg) = parse(&action).filter(|m| m.params.len() == 1) else {
                    self.numeric(id, 476, &format!("{} :Bad channel mask", p[1]));
                    return;
                };
                if let Some(route) = self.clients[&target].route {
                    self.link_send(
                        route,
                        &format!(
                            "FORCE {} {} {}",
                            self.clients[&id].uid,
                            self.clients[&target].uid,
                            network::encode(&action)
                        ),
                    );
                } else {
                    let source = self.clients[&id].prefix();
                    self.force(target, &msg, &source);
                }
            }
            "SAMODE" => {
                if class != OperClass::Override {
                    self.numeric(id, 481, ":Channel override privileges required");
                    return;
                }
                if !p[0].starts_with('#') && !p[0].starts_with('&') {
                    self.numeric(id, 502, ":SAMODE requires a channel target");
                    return;
                }
                self.mode(id, p);
            }
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn host_masks() {
        assert!(matches("127.*", "127.0.0.1"));
        assert!(matches("::?", "::1"));
        assert!(!matches("127.*", "192.0.2.1"));
        assert!(matches("*", "127.0.0.1"));
    }
}
