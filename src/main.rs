use std::{env, io, net::TcpListener};
use yamircd::{serve, Config};

fn main() -> io::Result<()> {
    let mut config = Config::default();
    let mut config_file = None;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => config.listen = value(&mut args, &arg)?,
            "--name" => config.name = value(&mut args, &arg)?,
            "--description" => config.description = value(&mut args, &arg)?,
            "--link-listen" => config.link_listen = Some(value(&mut args, &arg)?),
            "--config" => config_file = Some(value(&mut args, &arg)?),
            "--help" | "-h" => {
                println!("YamIRCd\nUsage: yamircd [--listen 127.0.0.1:6667] [--name irc.local] [--description \"YamIRC server\"] [--link-listen 127.0.0.1:7000] [--config yamircd.conf]\nOptional environment variable: YAMIRCD_PASSWORD (connection password)\nConfig rows: oper NAME IP_MASK local|global|override PASSWORD_ENV\n             link SERVER ADDRESS_OR_- INCOMING_IP PASSWORD_ENV\n             services SERVER INCOMING_IP PASSWORD_ENV");
                return Ok(());
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Unknown option: {arg}"),
                ))
            }
        }
    }
    config.password = env::var("YAMIRCD_PASSWORD").ok().filter(|s| !s.is_empty());
    if let Some(path) = config_file {
        read_config(&path, &mut config)?;
    }
    config.validate()?;
    let listener = TcpListener::bind(&config.listen)?;
    eprintln!(
        "YamIRCd listening on {} as {}",
        listener.local_addr()?,
        config.name
    );
    serve(listener, config)
}

fn read_config(path: &str, config: &mut Config) -> io::Result<()> {
    for (index, line) in std::fs::read_to_string(path)?.lines().enumerate() {
        let line = line.split('#').next().unwrap().trim();
        if line.is_empty() {
            continue;
        }
        let p: Vec<_> = line.split_whitespace().collect();
        let invalid = || {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Invalid config row {} (or missing secret environment variable)",
                    index + 1
                ),
            )
        };
        // Every row ends with the name of the environment variable holding its secret.
        let fields = if p.first() == Some(&"services") { 4 } else { 5 };
        if p.len() != fields {
            return Err(invalid());
        }
        let password = env::var(p[fields - 1])
            .ok()
            .filter(|s| !s.is_empty())
            .ok_or_else(invalid)?;
        match p[0] {
            "services" => config.services.push(yamircd::ServicesConfig {
                name: p[1].into(),
                incoming_ip: p[2].parse().map_err(|_| invalid())?,
                password,
            }),
            "oper" => config.opers.push(yamircd::OperConfig {
                name: p[1].into(),
                host: p[2].into(),
                class: yamircd::OperClass::parse(p[3]).ok_or_else(invalid)?,
                password,
            }),
            "link" => config.links.push(yamircd::LinkConfig {
                name: p[1].into(),
                address: if p[2] == "-" {
                    None
                } else {
                    Some(p[2].parse().map_err(|_| invalid())?)
                },
                incoming_ip: p[3].parse().map_err(|_| invalid())?,
                password,
            }),
            _ => return Err(invalid()),
        }
    }
    Ok(())
}

fn value(args: &mut impl Iterator<Item = String>, option: &str) -> io::Result<String> {
    args.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Missing value for {option}"),
        )
    })
}
