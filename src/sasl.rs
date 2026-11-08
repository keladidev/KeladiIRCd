//! SASL PLAIN (IRCv3), checked against Anope through its JSON-RPC interface
//! (`anope.checkCredentials`), since Anope's ngIRCd protocol module has no SASL.
//! The check runs on its own thread so a slow services server never holds the
//! state lock.
use super::*;
use std::net::ToSocketAddrs;

#[derive(Clone)]
pub struct SaslConfig {
    /// `host:port` of Anope's httpd.
    pub address: String,
    /// The JSON-RPC page, normally `/jsonrpc`.
    pub path: String,
    /// A jsonrpc `token` from Anope's configuration, sent as a Bearer token.
    pub token: String,
}

/// Longest decoded SASL message accepted (account, password and separators).
const MAX_SASL: usize = 800;

fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let value = |c: u8| match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    };
    let bytes = text.as_bytes();
    if bytes.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for (i, chunk) in bytes.chunks(4).enumerate() {
        let last = i == bytes.len() / 4 - 1;
        let pad = chunk.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut n = 0u32;
        for &c in &chunk[..4 - pad] {
            n = n << 6 | u32::from(value(c)?);
        }
        n <<= 6 * pad as u32;
        out.extend_from_slice(&n.to_be_bytes()[1..4 - pad]);
    }
    Some(out)
}

fn base64_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, &b)| n | u32::from(b) << (16 - 8 * i));
        for i in 0..4 {
            out.push(if i <= chunk.len() {
                DIGITS[(n >> (18 - 6 * i) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    out
}

fn json_string(text: &str) -> String {
    let mut out = String::from('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The string value of `"key"` in `json`, or None. Enough for Anope's flat replies.
fn json_field(json: &str, key: &str) -> Option<String> {
    let start = json.find(&format!("\"{key}\""))? + key.len() + 2;
    let rest = json[start..].trim_start().strip_prefix(':')?.trim_start();
    let mut chars = rest.strip_prefix('"')?.chars();
    let mut out = String::new();
    loop {
        match chars.next()? {
            '"' => return Some(out),
            '\\' => out.push(match chars.next()? {
                'n' => '\n',
                't' => '\t',
                'r' => '\r',
                'b' => '\u{8}',
                'f' => '\u{c}',
                'u' => {
                    let hex: String = chars.by_ref().take(4).collect();
                    char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?
                }
                c => c,
            }),
            c => out.push(c),
        }
    }
}

/// Splits a PLAIN message `authzid\0authcid\0password`. Logging in as another
/// account (an authzid different from the authcid) is not supported.
fn plain(message: &[u8]) -> Option<(String, String)> {
    let text = std::str::from_utf8(message).ok()?;
    let mut parts = text.split('\0');
    let (authzid, account, password) = (parts.next()?, parts.next()?, parts.next()?);
    let valid = parts.next().is_none()
        && (authzid.is_empty() || authzid == account)
        && services::account_valid(account)
        && !password.is_empty();
    valid.then(|| (account.into(), password.into()))
}

/// Asks Anope whether the credentials are right: Ok(Some(account)) if they are,
/// Ok(None) if not, Err if services could not answer.
fn check(config: &SaslConfig, account: &str, password: &str) -> Result<Option<String>, String> {
    let timeout = Some(Duration::from_secs(5));
    let address = config
        .address
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or("No address")?;
    let mut stream =
        TcpStream::connect_timeout(&address, Duration::from_secs(5)).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(timeout)
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(timeout)
        .map_err(|e| e.to_string())?;
    let body = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"anope.checkCredentials\",\"params\":[{},{}]}}",
        json_string(account),
        json_string(password)
    );
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        config.path,
        config.address,
        // Anope base64-decodes the Bearer token before comparing it.
        base64_encode(config.token.as_bytes()),
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut reply = String::new();
    stream
        .take(65536)
        .read_to_string(&mut reply)
        .map_err(|e| e.to_string())?;
    let (head, json) = reply.split_once("\r\n\r\n").ok_or("Malformed HTTP reply")?;
    if !head.starts_with("HTTP/1.1 200") && !head.starts_with("HTTP/1.0 200") {
        return Err(head.lines().next().unwrap_or_default().into());
    }
    if json.contains("\"result\"") {
        let account = json_field(json, "account").ok_or("No account in reply")?;
        return Ok(services::account_valid(&account).then_some(account));
    }
    // Anope's own codes, from -32099 (ERR_CUSTOM_START): no such account, wrong
    // password, suspended. Anything else (a bad token, say) is a setup problem.
    let code = json
        .split("\"code\"")
        .nth(1)
        .and_then(|rest| rest.trim_start().strip_prefix(':'))
        .and_then(|rest| {
            let end = rest.find([',', '}']).unwrap_or(rest.len());
            rest[..end].trim().parse::<i64>().ok()
        });
    match code {
        Some(-32099..=-32097) => Ok(None),
        _ => Err(json_field(json, "message").unwrap_or_else(|| "No result".into())),
    }
}

impl Server {
    /// AUTHENTICATE: a mechanism, then base64 chunks of up to 400 bytes, `+` ending
    /// a message that fills the last chunk exactly, or `*` to abort.
    pub(crate) fn authenticate(&mut self, id: u64, param: &str) {
        let c = &self.clients[&id];
        let fail = |server: &mut Self, code: u16, text: &str| {
            server.clients.get_mut(&id).unwrap().sasl = None;
            server.numeric(id, code, text);
        };
        if self.config.sasl.is_none() || !c.cap_sasl {
            return fail(self, 904, ":SASL authentication failed");
        }
        if c.registered || !c.account.is_empty() {
            return fail(self, 907, ":You have already authenticated using SASL");
        }
        if c.sasl_checking {
            return;
        }
        if param == "*" {
            return fail(self, 906, ":SASL authentication aborted");
        }
        let Some(buffer) = &c.sasl else {
            if param.eq_ignore_ascii_case("PLAIN") {
                self.clients.get_mut(&id).unwrap().sasl = Some(String::new());
                self.send(id, "AUTHENTICATE +");
            } else {
                self.numeric(id, 908, "PLAIN :are available SASL mechanisms");
                fail(self, 904, ":SASL authentication failed");
            }
            return;
        };
        let mut buffer = buffer.clone();
        if param != "+" {
            buffer.push_str(param);
        }
        if buffer.len() > MAX_SASL * 4 / 3 + 4 || param.len() > 400 {
            return fail(self, 905, ":SASL message too long");
        }
        if param.len() == 400 {
            self.clients.get_mut(&id).unwrap().sasl = Some(buffer);
            return;
        }
        let Some((account, password)) = base64_decode(&buffer).as_deref().and_then(plain) else {
            fail(self, 904, ":SASL authentication failed");
            return self.auth_failed(id);
        };
        let c = self.clients.get_mut(&id).unwrap();
        (c.sasl, c.sasl_checking) = (None, true);
        let (uid, weak) = (c.uid.clone(), self.weak.clone());
        let config = self.config.sasl.clone().unwrap();
        thread::spawn(move || {
            let result = check(&config, &account, &password);
            if let Some(server) = weak.upgrade() {
                server.lock().unwrap().sasl_checked(id, &uid, result);
            }
        });
    }

    fn sasl_checked(&mut self, id: u64, uid: &str, result: Result<Option<String>, String>) {
        let Some(c) = self.clients.get_mut(&id).filter(|c| c.uid == uid) else {
            return;
        };
        c.sasl_checking = false;
        match result {
            Ok(Some(account)) => {
                c.account = account.clone();
                let nick = if c.nick.is_empty() { "*" } else { &c.nick };
                let identity = format!("{nick}!~{}@{}", c.user, c.shown());
                self.numeric(
                    id,
                    900,
                    &format!("{identity} {account} :You are now logged in as {account}"),
                );
                self.numeric(id, 903, ":SASL authentication successful");
            }
            Ok(None) => {
                self.numeric(id, 904, ":SASL authentication failed");
                self.auth_failed(id);
            }
            Err(why) => {
                eprintln!("SASL check failed: {why}");
                self.numeric(id, 904, ":SASL authentication failed");
            }
        }
        // Registration may have finished negotiating while the check ran; a failed
        // login leaves the client free to register without an account.
        if self.clients.contains_key(&id) {
            self.register(id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(
            base64_decode("AGFsaWNlAHNlY3JldA==").unwrap(),
            b"\0alice\0secret"
        );
        assert_eq!(base64_decode("YWJj").unwrap(), b"abc");
        assert_eq!(base64_decode("YQ==").unwrap(), b"a");
        for text in ["", "a", "ab", "abc", "rpc-secret"] {
            let encoded = base64_encode(text.as_bytes());
            assert_eq!(base64_decode(&encoded).unwrap(), text.as_bytes());
        }
        assert_eq!(base64_encode(b"oper-secret"), "b3Blci1zZWNyZXQ=");
        for bad in ["YQ=", "Y===", "YQ==YWJj", "Y!Jj"] {
            assert!(base64_decode(bad).is_none(), "{bad}");
        }
        assert_eq!(
            plain(b"\0alice\0secret"),
            Some(("alice".into(), "secret".into()))
        );
        assert_eq!(
            plain(b"alice\0alice\0pw"),
            Some(("alice".into(), "pw".into()))
        );
        assert_eq!(plain(b"bob\0alice\0pw"), None);
        assert_eq!(plain(b"\0alice\0"), None);
        assert_eq!(json_string("a\"b\\c\n"), "\"a\\\"b\\\\c\\u000a\"");
        let reply = r#"{"jsonrpc":"2.0","id":1,"result":{"account": "Al\"ice!","confirmed":true}}"#;
        assert_eq!(json_field(reply, "account").as_deref(), Some("Al\"ice!"));
        assert_eq!(json_field(reply, "missing"), None);
    }
}
