//! UnrealIRCd-style mode tables and the helpers behind them: flood protection
//! (+f/+F), join throttling (+j), history (+H), extended bans, cloaked hosts (+x),
//! colour stripping (+S) and the bad-word filter (+G).
use super::*;
use std::net::IpAddr;

/// User modes a client may set or unset on itself.
pub(crate) const USER_SETTABLE: &str = "BdDGipRTwxZ";
/// User modes only IRC operators may set; they go when operator status does.
pub(crate) const OPER_ONLY: &str = "HIqsW";
/// User modes carried in USER records. `o` travels as the operator class and `t`
/// follows the vhost, so neither is listed.
pub(crate) const REPLICATED_UMODES: &str = "BdDGHIipqrRsSTwWxzZ";
/// Every user mode, for 004.
pub(crate) const USER_MODES: &str = "BdDGHIioqrRsStTwWxzZ";
/// Channel modes without a parameter. `r` is set by services, `Z` and `d` by the server.
pub(crate) const CHAN_FLAGS: &str = "cdimnprstzCDGKMNOPQRSTVZ";
/// Channel modes that take a parameter only when set, besides `l`.
pub(crate) const CHAN_PARAMS: &str = "fFHjL";
/// Every channel mode letter, for 004 and unknown-mode checks.
pub(crate) const CHAN_MODES: &str = "abcdefhijklmnopqrstvzCDFGHIJKLMNOPQRSTVZ";
/// Server notice masks (+s): client connects (c) and far connects (F), G/K-lines (G),
/// kills (k), nick changes here (n) and elsewhere (N), operator logins (o), links (s),
/// vhosts (v).
pub(crate) const SNOMASKS: &str = "cFGknNosv";
pub(crate) const DEFAULT_SNOMASK: &str = "cFGkosv";

/// One `+f` rule: more than `count` events of `kind` within the spec's seconds
/// triggers `action`, which is undone after `minutes` (0 keeps it).
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct FloodRule {
    pub kind: char,
    pub count: u32,
    pub action: char,
    pub minutes: u32,
}

#[derive(Debug, PartialEq)]
pub(crate) struct FloodSpec {
    pub rules: Vec<FloodRule>,
    pub seconds: u32,
}

/// Parses `+f` values: `[7c#C15,30j#R5,10k#K15,40m#M10,8n#N15,5t#b,3r]:15`, or the
/// short form `7:15` / `*7:15` (lines per user; `*` bans as well as kicks).
/// Kinds: c CTCPs, j joins, k knocks, m messages, n nick changes (channel-wide);
/// t lines and r repeats per user. Actions are the channel mode to set, or for
/// t and r, k (kick) or b (ban and kick).
pub(crate) fn parse_flood(value: &str) -> Option<FloodSpec> {
    let (body, seconds) = value.rsplit_once(':')?;
    let seconds: u32 = seconds.parse().ok().filter(|s| (1..=999).contains(s))?;
    let count = |text: &str| text.parse::<u32>().ok().filter(|c| (1..=999).contains(c));
    let Some(inner) = body.strip_prefix('[').and_then(|b| b.strip_suffix(']')) else {
        let (ban, lines) = body
            .strip_prefix('*')
            .map_or((false, body), |rest| (true, rest));
        let action = if ban { 'b' } else { 'k' };
        let (kind, count, minutes) = ('t', count(lines)?, 0);
        return Some(FloodSpec {
            rules: vec![FloodRule {
                kind,
                count,
                action,
                minutes,
            }],
            seconds,
        });
    };
    let mut rules: Vec<FloodRule> = Vec::new();
    for part in inner.split(',') {
        let (head, action) = part
            .split_once('#')
            .map_or((part, None), |(h, a)| (h, Some(a)));
        let kind = head.chars().last()?;
        let (default, allowed) = match kind {
            'c' => ('C', "CmM"),
            'j' => ('i', "iR"),
            'k' => ('K', "K"),
            'm' => ('m', "mM"),
            'n' => ('N', "N"),
            't' | 'r' => ('k', "kb"),
            _ => return None,
        };
        let count = count(head.strip_suffix(kind)?)?;
        let (action, minutes) = match action {
            None => (default, 0),
            Some(a) => {
                let action = a.chars().next()?;
                let rest = &a[action.len_utf8()..];
                let minutes = if rest.is_empty() {
                    0
                } else {
                    rest.parse().ok().filter(|m| (1..=999).contains(m))?
                };
                (action, minutes)
            }
        };
        if !allowed.contains(action) || rules.iter().any(|r| r.kind == kind) {
            return None;
        }
        rules.push(FloodRule {
            kind,
            count,
            action,
            minutes,
        });
    }
    Some(FloodSpec { rules, seconds })
}

/// `+F` profiles, as `+f` specs (modelled on UnrealIRCd's).
pub(crate) fn flood_profile(name: &str) -> Option<&'static str> {
    Some(match name {
        "very-strict" => "[7c#C15,20j#R5,8k#K15,30m#M10,6n#N15]:15",
        "strict" => "[7c#C15,25j#R5,10k#K15,35m#M10,8n#N15]:15",
        "normal" => "[7c#C15,30j#R5,10k#K15,40m#M10,8n#N15]:15",
        "relaxed" => "[10c#C15,45j#R5,15k#K15,60m#M10,10n#N15]:15",
        "very-relaxed" => "[15c#C15,60j#R5,20k#K15,90m#M10,12n#N15]:15",
        _ => return None,
    })
}

/// `+j joins:seconds`, per user.
pub(crate) fn parse_throttle(value: &str) -> Option<(u32, u64)> {
    let (joins, seconds) = value.split_once(':')?;
    let joins = joins.parse().ok().filter(|j| (1..=255).contains(j))?;
    let seconds = seconds.parse().ok().filter(|s| (1..=999).contains(s))?;
    Some((joins, seconds))
}

/// `+H lines:time`: at most 200 lines, kept up to 7 days. The time is in minutes,
/// or ends in m, h or d.
pub(crate) fn parse_history(value: &str) -> Option<(usize, u64)> {
    let (lines, time) = value.split_once(':')?;
    let lines = lines.parse().ok().filter(|l| (1..=200).contains(l))?;
    let (number, unit) = match time.strip_suffix(['m', 'h', 'd']) {
        Some(number) => (number, &time[number.len()..]),
        None => (time, "m"),
    };
    let minutes = number.parse::<u64>().ok()?
        * match unit {
            "h" => 60,
            "d" => 1440,
            _ => 1,
        };
    (1..=10_080)
        .contains(&minutes)
        .then_some((lines, minutes * 60))
}

/// Extended bans by name and letter. `~a:x` is stored as `~account:x`.
const EXTBANS: [(char, &str); 13] = [
    ('a', "account"),
    ('c', "channel"),
    ('f', "forward"),
    ('G', "securitygroup"),
    ('j', "join"),
    ('m', "msgbypass"),
    ('n', "nickchange"),
    ('O', "operclass"),
    ('p', "partmsg"),
    ('q', "quiet"),
    ('r', "realname"),
    ('t', "time"),
    ('T', "text"),
];
/// Extbans that select users; the others say what a matching user may not do.
const MATCHERS: [&str; 5] = [
    "account",
    "channel",
    "operclass",
    "realname",
    "securitygroup",
];
pub(crate) const EXTBAN_LETTERS: &str = "acfGjmnOpqrtT";
pub(crate) const SECURITY_GROUPS: [&str; 4] = [
    "known-users",
    "unknown-users",
    "tls-users",
    "tls-and-known-users",
];
/// What `~msgbypass:<what>:` lets an excepted user past.
const BYPASSES: [&str; 6] = ["external", "moderated", "censor", "color", "notice", "ctcp"];

fn extban_name(name: &str) -> Option<&'static str> {
    EXTBANS
        .iter()
        .find(|(letter, full)| name == *full || name.chars().eq([*letter]))
        .map(|(_, full)| *full)
}

/// A user selector: a `nick!user@host` mask or a matcher extban.
fn matcher(raw: &str) -> Option<String> {
    let Some(rest) = raw.strip_prefix('~') else {
        let mask = channel::normalize_mask(raw);
        return (!mask.is_empty() && !mask.contains([',', ' '])).then_some(mask);
    };
    let (name, value) = rest.split_once(':')?;
    let name = extban_name(name).filter(|n| MATCHERS.contains(n))?;
    let valid = match name {
        "channel" => {
            let chan = value.trim_start_matches(['~', '&', '@', '%', '+']);
            value.len() - chan.len() <= 1 && channel_valid(chan)
        }
        "securitygroup" => SECURITY_GROUPS.contains(&value),
        _ => !value.is_empty() && !value.contains([',', ' ']),
    };
    valid.then(|| format!("~{name}:{value}"))
}

/// Validates and normalizes a ban (`b`), exception (`e`) or invite exception (`I`)
/// entry, so that `~q:bob` is stored as `~quiet:bob!*@*`.
pub(crate) fn list_entry(raw: &str, list: char) -> Option<String> {
    entry(raw, list, true).filter(|e| e.len() <= 100)
}

fn entry(raw: &str, list: char, outer: bool) -> Option<String> {
    let Some(rest) = raw.strip_prefix('~') else {
        return matcher(raw);
    };
    let (name, value) = rest.split_once(':')?;
    let name = extban_name(name)?;
    if MATCHERS.contains(&name) {
        return matcher(raw);
    }
    let value = match name {
        "quiet" | "nickchange" | "join" | "partmsg" if list != 'I' => matcher(value)?,
        "forward" if list == 'b' => {
            let (chan, who) = value.split_once(':')?;
            if !chan.starts_with('#') || !channel_valid(chan) {
                return None;
            }
            format!("{chan}:{}", matcher(who)?)
        }
        "time" if outer => {
            let (minutes, inner) = value.split_once(':')?;
            minutes
                .parse::<u32>()
                .ok()
                .filter(|m| (1..=9999).contains(m))?;
            format!("{minutes}:{}", entry(inner, list, false)?)
        }
        "text" if list == 'b' => {
            let (how, pattern) = value.split_once(':')?;
            if !matches!(how, "block" | "censor") || pattern.is_empty() {
                return None;
            }
            value.to_string()
        }
        "msgbypass" if list == 'e' => {
            let (what, who) = value.split_once(':')?;
            if !BYPASSES.contains(&what) {
                return None;
            }
            format!("{what}:{}", matcher(who)?)
        }
        _ => return None,
    };
    let entry = format!("~{name}:{value}");
    (!entry.contains([',', ' '])).then_some(entry)
}

/// Minutes until a `~time:<minutes>:` entry expires.
pub(crate) fn entry_minutes(entry: &str) -> Option<u64> {
    entry
        .strip_prefix("~time:")?
        .split(':')
        .next()?
        .parse()
        .ok()
}

/// A cloaked host (+x): keyed hashes of the address and its networks, so a ban on
/// a cloaked /24 (`*.ABCD1234.89ABCDEF.IP`) still works without showing the address.
pub(crate) fn cloak(key: &[u8], host: &str) -> String {
    let hash = |text: &str| {
        let digest = crypto::hmac_sha256(key, text.as_bytes());
        digest[..4]
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<String>()
    };
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            let o = ip.octets();
            format!(
                "{}.{}.{}.IP",
                hash(host),
                hash(&format!("{}.{}.{}", o[0], o[1], o[2])),
                hash(&format!("{}.{}", o[0], o[1]))
            )
        }
        Ok(IpAddr::V6(ip)) => {
            let s = ip.segments();
            format!(
                "{}:{}:{}:IP",
                hash(&ip.to_string()),
                hash(&format!("{:x}:{:x}:{:x}:{:x}", s[0], s[1], s[2], s[3])),
                hash(&format!("{:x}:{:x}:{:x}", s[0], s[1], s[2]))
            )
        }
        Err(_) => format!("Clk-{}", hash(host)),
    }
}

/// Removes mIRC colours and formatting (+S).
pub(crate) fn strip_formatting(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\x02' | '\x0f' | '\x11' | '\x16' | '\x1d' | '\x1e' | '\x1f' => {}
            // \x03 takes up to two digits, then optionally a comma and two more;
            // \x04 the same with six hex digits.
            '\x03' | '\x04' => {
                let (width, digit): (usize, fn(&char) -> bool) = if c == '\x03' {
                    (2, char::is_ascii_digit)
                } else {
                    (6, char::is_ascii_hexdigit)
                };
                if skip_digits(&mut chars, width, digit) > 0 && chars.peek() == Some(&',') {
                    let mut ahead = chars.clone();
                    ahead.next();
                    if ahead.peek().is_some_and(digit) {
                        chars.next();
                        skip_digits(&mut chars, width, digit);
                    }
                }
            }
            _ => out.push(c),
        }
    }
    out
}

fn skip_digits(
    chars: &mut std::iter::Peekable<std::str::Chars>,
    width: usize,
    digit: fn(&char) -> bool,
) -> usize {
    let mut n = 0;
    while n < width && chars.peek().is_some_and(digit) {
        chars.next();
        n += 1;
    }
    n
}

pub(crate) fn has_color(text: &str) -> bool {
    text.contains(['\x03', '\x04'])
}

/// A CTCP other than ACTION.
pub(crate) fn is_ctcp(text: &str) -> bool {
    text.starts_with('\x01') && !text.starts_with("\x01ACTION ")
}

/// Replaces words matching a bad word (lower case, `*`/`?` wildcards) with `<censored>`.
pub(crate) fn censor(text: &str, words: &[String]) -> String {
    if words.is_empty() {
        return text.into();
    }
    text.split(' ')
        .map(|token| {
            let core: String = token
                .chars()
                .filter(|c| c.is_alphanumeric())
                .collect::<String>()
                .to_lowercase();
            if !core.is_empty() && words.iter().any(|w| oper::matches(w, &core)) {
                "<censored>"
            } else {
                token
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Channel-wide flood counters (+f kinds c, j, k, m, n) and per-user ones (t, r).
#[derive(Default)]
pub(crate) struct Flood {
    counts: BTreeMap<char, (Instant, u32)>,
    /// Lines in the window, the last line, and how often it was repeated.
    users: BTreeMap<u64, (Instant, u32, String, u32)>,
}

impl Flood {
    /// Counts one event; the rule it breaks, if any. A broken rule's counter starts
    /// again, so it triggers once per burst.
    pub(crate) fn hit(
        &mut self,
        spec: &FloodSpec,
        kind: char,
        user: u64,
        text: &str,
    ) -> Option<FloodRule> {
        let rule = spec.rules.iter().find(|r| r.kind == kind)?;
        let window = Duration::from_secs(spec.seconds.into());
        let now = Instant::now();
        let over = if matches!(kind, 't' | 'r') {
            let entry = self
                .users
                .entry(user)
                .or_insert_with(|| (now, 0, String::new(), 0));
            if now.duration_since(entry.0) >= window {
                *entry = (now, 0, String::new(), 0);
            }
            entry.1 += 1;
            entry.3 = if entry.2 == text { entry.3 + 1 } else { 0 };
            entry.2 = text.into();
            let n = if kind == 't' { entry.1 } else { entry.3 };
            if n > rule.count {
                *entry = (now, 0, String::new(), 0);
            }
            n > rule.count
        } else {
            let entry = self.counts.entry(kind).or_insert((now, 0));
            if now.duration_since(entry.0) >= window {
                *entry = (now, 0);
            }
            entry.1 += 1;
            let over = entry.1 > rule.count;
            if over {
                *entry = (now, 0);
            }
            over
        };
        over.then(|| rule.clone())
    }

    pub(crate) fn forget(&mut self, user: u64) {
        self.users.remove(&user);
    }
}

/// A mode the server takes off later: an +f action or a `~time` list entry.
pub(crate) struct Timed {
    pub at: u64,
    pub key: String,
    pub mode: char,
    pub param: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flood_specs() {
        let spec = parse_flood("[7c#C15,30j,5t#b,3r]:15").unwrap();
        assert_eq!(spec.seconds, 15);
        assert_eq!(
            spec.rules[0],
            FloodRule {
                kind: 'c',
                count: 7,
                action: 'C',
                minutes: 15
            }
        );
        assert_eq!((spec.rules[1].action, spec.rules[2].action), ('i', 'b'));
        assert_eq!(parse_flood("*5:10").unwrap().rules[0].action, 'b');
        assert_eq!(parse_flood("5:10").unwrap().rules[0].action, 'k');
        for bad in [
            "",
            "5",
            "[5x]:10",
            "[5c#i]:10",
            "[5c,6c]:10",
            "[0m]:5",
            "[5m]:0",
            "[é]:5",
        ] {
            assert!(parse_flood(bad).is_none(), "{bad}");
        }
        for name in ["very-strict", "strict", "normal", "relaxed", "very-relaxed"] {
            assert!(parse_flood(flood_profile(name).unwrap()).is_some());
        }
        assert_eq!(parse_throttle("3:10"), Some((3, 10)));
        assert_eq!(parse_history("15:1d"), Some((15, 86_400)));
        assert_eq!(parse_history("10:30"), Some((10, 1800)));
        assert!(parse_history("10:8d").is_none() && parse_throttle("0:5").is_none());

        let spec = parse_flood("[2m,1r]:60").unwrap();
        let mut flood = Flood::default();
        assert!(flood.hit(&spec, 'm', 1, "a").is_none());
        assert!(flood.hit(&spec, 'm', 1, "b").is_none());
        assert_eq!(flood.hit(&spec, 'm', 1, "c").unwrap().action, 'm');
        assert!(flood.hit(&spec, 'r', 1, "same").is_none());
        assert!(flood.hit(&spec, 'r', 1, "same").is_none());
        assert!(flood.hit(&spec, 'r', 1, "same").is_some());
    }

    #[test]
    fn extbans() {
        assert_eq!(list_entry("bob", 'b').unwrap(), "bob!*@*");
        assert_eq!(list_entry("~q:bob", 'b').unwrap(), "~quiet:bob!*@*");
        assert_eq!(list_entry("~a:Alice", 'b').unwrap(), "~account:Alice");
        assert_eq!(
            list_entry("~t:5:~q:~a:x", 'b').unwrap(),
            "~time:5:~quiet:~account:x"
        );
        assert_eq!(
            list_entry("~f:#over:*!*@h", 'b').unwrap(),
            "~forward:#over:*!*@h"
        );
        assert_eq!(list_entry("~channel:@#ops", 'e').unwrap(), "~channel:@#ops");
        assert_eq!(
            list_entry("~T:censor:darn", 'b').unwrap(),
            "~text:censor:darn"
        );
        assert_eq!(
            list_entry("~m:moderated:~a:*", 'e').unwrap(),
            "~msgbypass:moderated:~account:*"
        );
        for (bad, list) in [
            ("~x:y", 'b'),
            ("~q:~q:x", 'b'),
            ("~t:5:~t:5:x", 'b'),
            ("~m:moderated:x", 'b'),
            ("~T:shout:x", 'b'),
            ("~G:everyone", 'b'),
            ("~channel:#a b", 'b'),
            ("~f:nochan:x", 'b'),
            ("a,b", 'b'),
        ] {
            assert!(list_entry(bad, list).is_none(), "{bad}");
        }
        assert_eq!(entry_minutes("~time:5:x!*@*"), Some(5));
    }

    #[test]
    fn text_helpers() {
        let key = b"key";
        let c = cloak(key, "192.0.2.1");
        assert!(c.ends_with(".IP") && c.len() == 29, "{c}");
        assert_eq!(c[9..], cloak(key, "192.0.2.99")[9..]);
        assert_ne!(c[..8], cloak(key, "192.0.2.99")[..8]);
        assert!(cloak(key, "2001:db8::1").ends_with(":IP"));
        assert!(services::host_valid(&c) && services::host_valid(&cloak(key, "::1")));
        assert_eq!(
            strip_formatting("\x02b\x02 \x0304,12red\x03 \x031,x \x04FF00FFhex"),
            "b red ,x hex"
        );
        assert!(has_color("\x0304x") && !has_color("\x02x"));
        assert!(is_ctcp("\x01VERSION\x01") && !is_ctcp("\x01ACTION waves\x01"));
        let words = vec!["darn".to_string(), "heck*".to_string()];
        assert_eq!(
            censor("Darn! what the heckity", &words),
            "<censored> what the <censored>"
        );
    }
}
