//! Reads the TOML configuration file. `examples/keladiircd.toml` documents every key.
// shortcut: a hand-written TOML subset (tables, [[arrays]], strings, whole numbers)
// keeps the crate dependency-free; switch to the toml crate if the format needs more.
use crate::{Config, LinkConfig, OperClass, OperConfig, SaslConfig, ServicesConfig};
use std::{io, str::FromStr};

enum Value {
    Str(String),
    Int(i64),
}

/// One `[section]` or `[[section]]` block; the first one is the top level ("").
struct Table {
    header: String,
    line: usize,
    keys: Vec<(String, Value, usize)>,
}

impl Config {
    /// Reads a TOML file over the current settings. Secrets come from the
    /// environment variables the file names.
    pub fn load(&mut self, path: &str) -> io::Result<()> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| io::Error::new(e.kind(), format!("{path}: {e}")))?;
        self.apply_toml(&text, |name| std::env::var(name).ok())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{path}, {e}")))
    }

    fn apply_toml(
        &mut self,
        text: &str,
        env: impl Fn(&str) -> Option<String>,
    ) -> Result<(), String> {
        for mut t in parse(text)? {
            match t.header.as_str() {
                "" => {
                    let top = [
                        ("name", &mut self.name),
                        ("description", &mut self.description),
                        ("listen", &mut self.listen),
                        ("modes_on_connect", &mut self.modes_on_connect),
                    ];
                    for (key, field) in top {
                        if let Some((value, _)) = t.string(key)? {
                            *field = value;
                        }
                    }
                    for (key, field) in [
                        ("link_listen", &mut self.link_listen),
                        ("proxy_listen", &mut self.proxy_listen),
                    ] {
                        if let Some((value, _)) = t.string(key)? {
                            *field = Some(value);
                        }
                    }
                    if let Some(value) = t.int("max_users")? {
                        self.max_users = value;
                    }
                    if let Some((words, _)) = t.string("badwords")? {
                        self.badwords = words.split_whitespace().map(str::to_lowercase).collect();
                    }
                    if t.keys.iter().any(|k| k.0 == "cloak_key_env") {
                        self.cloak_key = Some(t.secret("cloak_key_env", &env)?);
                    }
                }
                "[[link]]" => self.links.push(LinkConfig {
                    name: t.required("name")?,
                    address: t.parsed("connect", "an IP:port address")?,
                    incoming_ip: t.required_parsed("incoming_ip", "an IP address")?,
                    password: t.secret("password_env", &env)?,
                }),
                "[[oper]]" => self.opers.push(OperConfig {
                    name: t.required("name")?,
                    host: t.required("ip_mask")?,
                    class: t.required_parsed("class", "local, global or override")?,
                    password: t.secret("password_env", &env)?,
                }),
                "[[services]]" => self.services.push(ServicesConfig {
                    name: t.required("name")?,
                    incoming_ip: t.required_parsed("incoming_ip", "an IP address")?,
                    password: t.secret("password_env", &env)?,
                }),
                "[sasl]" if self.sasl.is_none() => {
                    self.sasl = Some(SaslConfig {
                        address: t.required("address")?,
                        path: t.string("path")?.map_or("/jsonrpc".into(), |(path, _)| path),
                        token: t.secret("token_env", &env)?,
                    })
                }
                "[sasl]" => return Err(format!("line {}: [sasl] appears twice", t.line)),
                other => {
                    return Err(format!(
                        "line {}: unknown section {other}; expected [[link]], [[oper]], [[services]] or [sasl]",
                        t.line
                    ))
                }
            }
            t.finish()?;
        }
        Ok(())
    }
}

impl FromStr for OperClass {
    type Err = ();
    fn from_str(value: &str) -> Result<Self, ()> {
        Self::parse(value).ok_or(())
    }
}

impl Table {
    fn place(&self) -> &str {
        if self.header.is_empty() {
            "the top level"
        } else {
            &self.header
        }
    }

    fn take(&mut self, key: &str) -> Option<(Value, usize)> {
        let index = self.keys.iter().position(|k| k.0 == key)?;
        let (_, value, line) = self.keys.remove(index);
        Some((value, line))
    }

    fn string(&mut self, key: &str) -> Result<Option<(String, usize)>, String> {
        match self.take(key) {
            None => Ok(None),
            Some((Value::Str(s), line)) => Ok(Some((s, line))),
            Some((_, line)) => Err(format!("line {line}: `{key}` must be a quoted string")),
        }
    }

    fn int(&mut self, key: &str) -> Result<Option<usize>, String> {
        match self.take(key) {
            None => Ok(None),
            Some((Value::Int(n), line)) => usize::try_from(n)
                .map(Some)
                .map_err(|_| format!("line {line}: `{key}` must not be negative")),
            Some((_, line)) => Err(format!("line {line}: `{key}` must be a whole number")),
        }
    }

    fn required_at(&mut self, key: &str) -> Result<(String, usize), String> {
        self.string(key)?
            .ok_or_else(|| format!("line {}: {} is missing `{key}`", self.line, self.place()))
    }

    fn required(&mut self, key: &str) -> Result<String, String> {
        Ok(self.required_at(key)?.0)
    }

    fn parse_at<T: FromStr>(
        key: &str,
        (value, line): (String, usize),
        what: &str,
    ) -> Result<T, String> {
        value
            .parse()
            .map_err(|_| format!("line {line}: `{key}` must be {what}, not \"{value}\""))
    }

    fn parsed<T: FromStr>(&mut self, key: &str, what: &str) -> Result<Option<T>, String> {
        self.string(key)?
            .map(|v| Self::parse_at(key, v, what))
            .transpose()
    }

    fn required_parsed<T: FromStr>(&mut self, key: &str, what: &str) -> Result<T, String> {
        Self::parse_at(key, self.required_at(key)?, what)
    }

    /// Looks up the environment variable that a `*_env` key names.
    fn secret(
        &mut self,
        key: &str,
        env: impl Fn(&str) -> Option<String>,
    ) -> Result<String, String> {
        let (name, line) = self.required_at(key)?;
        env(&name).filter(|s| !s.is_empty()).ok_or_else(|| {
            format!("line {line}: environment variable {name} (named by `{key}`) is not set or is empty")
        })
    }

    fn finish(self) -> Result<(), String> {
        match self.keys.first() {
            Some((key, _, line)) => Err(format!(
                "line {line}: unknown key `{key}` in {}",
                self.place()
            )),
            None => Ok(()),
        }
    }
}

fn parse(text: &str) -> Result<Vec<Table>, String> {
    let mut tables = vec![Table {
        header: String::new(),
        line: 1,
        keys: Vec::new(),
    }];
    for (index, line) in text.lines().enumerate() {
        let n = index + 1;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            let header: String = line.split('#').next().unwrap().split_whitespace().collect();
            if !header.ends_with(']') {
                return Err(format!("line {n}: expected [section] or [[section]]"));
            }
            tables.push(Table {
                header,
                line: n,
                keys: Vec::new(),
            });
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            if matches!(
                line.split_whitespace().next(),
                Some("link" | "oper" | "services" | "sasl")
            ) {
                return Err(format!(
                    "line {n}: this is the old line-based config format. KeladiIRCd now reads TOML; \
                     see \"Upgrading from the line-based config\" in README.md"
                ));
            }
            return Err(format!(
                "line {n}: expected key = value, [section] or [[section]]"
            ));
        };
        let key = key.trim();
        if key.is_empty()
            || !key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        {
            return Err(format!("line {n}: invalid key `{key}`"));
        }
        let value = parse_value(value.trim()).map_err(|e| format!("line {n}: `{key}`: {e}"))?;
        let table = tables.last_mut().unwrap();
        if table.keys.iter().any(|k| k.0 == key) {
            return Err(format!(
                "line {n}: `{key}` is set twice in {}",
                table.place()
            ));
        }
        table.keys.push((key.into(), value, n));
    }
    Ok(tables)
}

fn parse_value(text: &str) -> Result<Value, &'static str> {
    let (value, rest) = if let Some(body) = text.strip_prefix('"') {
        let mut out = String::new();
        let mut chars = body.char_indices();
        let end = loop {
            match chars.next().ok_or("unterminated string")? {
                (i, '"') => break i + 1,
                (_, '\\') => out.push(match chars.next().map(|c| c.1) {
                    Some('"') => '"',
                    Some('\\') => '\\',
                    Some('n') => '\n',
                    Some('t') => '\t',
                    _ => return Err("unsupported escape (use \\\" \\\\ \\n or \\t)"),
                }),
                (_, c) => out.push(c),
            }
        };
        (Value::Str(out), &body[end..])
    } else if let Some(body) = text.strip_prefix('\'') {
        let (literal, rest) = body.split_once('\'').ok_or("unterminated string")?;
        (Value::Str(literal.into()), rest)
    } else {
        let number = text.split('#').next().unwrap().trim().replace('_', "");
        let number = number
            .parse()
            .map_err(|_| "expected a quoted string or a whole number")?;
        (Value::Int(number), "")
    };
    let rest = rest.trim();
    if rest.is_empty() || rest.starts_with('#') {
        Ok(value)
    } else {
        Err("unexpected text after the value")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load(text: &str) -> Result<Config, String> {
        let mut config = Config::default();
        config.apply_toml(text, |name| {
            (name != "UNSET").then(|| format!("{name}-value"))
        })?;
        Ok(config)
    }

    #[test]
    fn shipped_configs_load_and_validate() {
        for text in [
            include_str!("../examples/keladiircd.toml"),
            include_str!("../examples/a.toml"),
            include_str!("../examples/b.toml"),
            include_str!("../docker/alpha.toml"),
            include_str!("../docker/beta.toml"),
            include_str!("../docker/cypher.toml"),
        ] {
            load(text).unwrap().validate().unwrap();
        }
        let alpha = load(include_str!("../docker/alpha.toml")).unwrap();
        assert_eq!(alpha.name, "alpha.irc.test");
        assert_eq!(alpha.links.len(), 2);
        assert_eq!(alpha.links[0].address, None);
        assert_eq!(alpha.services[0].password, "SERVICES_SECRET-value");
        assert_eq!(alpha.sasl.as_ref().unwrap().path, "/jsonrpc");
        assert!(matches!(alpha.opers[0].class, OperClass::Override));
        let b = load(include_str!("../examples/b.toml")).unwrap();
        assert_eq!(b.links[0].address, Some("127.0.0.1:7001".parse().unwrap()));
    }

    #[test]
    fn mode_settings() {
        let config = load(
            "modes_on_connect = \"+ixw\"\nbadwords = \"Darn heck*\"\ncloak_key_env = \"CLOAK\"\n",
        )
        .unwrap();
        config.validate().unwrap();
        assert_eq!(config.modes_on_connect, "+ixw");
        assert_eq!(config.badwords, ["darn", "heck*"]);
        assert_eq!(config.cloak_key.as_deref(), Some("CLOAK-value"));
        let bad = load("modes_on_connect = \"+o\"\n").unwrap();
        assert!(bad.validate().is_err());
    }

    #[test]
    fn values_and_comments() {
        let config = load(
            "name = \"x.test\" # comment\ndescription = 'a # b'\nmax_users = 1_000\n\
             listen = \"say \\\"hi\\\"\"\n",
        )
        .unwrap();
        assert_eq!(config.name, "x.test");
        assert_eq!(config.description, "a # b");
        assert_eq!(config.max_users, 1000);
        assert_eq!(config.listen, "say \"hi\"");
    }

    #[test]
    fn errors_name_the_line_and_key() {
        for (text, error) in [
            (
                "link b.test - 127.0.0.1 S\n",
                "line 1: this is the old line-based config format",
            ),
            (
                "name = irc\n",
                "line 1: `name`: expected a quoted string or a whole number",
            ),
            (
                "max_users = \"5\"\n",
                "line 1: `max_users` must be a whole number",
            ),
            (
                "nmae = \"x\"\n",
                "line 1: unknown key `nmae` in the top level",
            ),
            (
                "name = \"a\"\nname = \"b\"\n",
                "line 2: `name` is set twice",
            ),
            ("[link]\n", "line 1: unknown section [link]"),
            (
                "\n[[link]]\nname = \"b\"\n",
                "line 2: [[link]] is missing `incoming_ip`",
            ),
            (
                "[[link]]\nname = \"b\"\nincoming_ip = \"nope\"\n",
                "line 3: `incoming_ip` must be an IP address, not \"nope\"",
            ),
            (
                "[[oper]]\nname = \"a\"\nip_mask = \"*\"\nclass = \"root\"\npassword_env = \"S\"\n",
                "line 4: `class` must be local, global or override",
            ),
            (
                "[sasl]\naddress = \"127.0.0.1:8080\"\ntoken_env = \"UNSET\"\n",
                "line 3: environment variable UNSET (named by `token_env`) is not set",
            ),
            ("name = \"x", "line 1: `name`: unterminated string"),
        ] {
            let got = load(text).err().unwrap();
            assert!(got.starts_with(error), "{text:?}: {got}");
        }
    }
}
