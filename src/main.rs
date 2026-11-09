use keladiircd::{serve, Config};
use std::{env, io, net::TcpListener};

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("KeladiIRCd\nUsage: keladiircd [--config keladiircd.toml] [--listen 127.0.0.1:6667] [--name irc.local] [--description \"KeladiIRC server\"] [--link-listen 127.0.0.1:7000] [--proxy-listen 127.0.0.1:6668] [--max-users 256]\nThe config file is TOML; examples/keladiircd.toml explains every key. Flags override the file.\nOptional environment variable: KELADIIRCD_PASSWORD (connection password)");
        return Ok(());
    }
    let mut config = Config::default();
    // Read the file first so command-line flags override it.
    if let Some(i) = args.iter().position(|a| a == "--config") {
        config.load(args.get(i + 1).ok_or_else(|| missing("--config"))?)?;
    }
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => config.listen = value(&mut args, &arg)?,
            "--name" => config.name = value(&mut args, &arg)?,
            "--description" => config.description = value(&mut args, &arg)?,
            "--link-listen" => config.link_listen = Some(value(&mut args, &arg)?),
            "--proxy-listen" => config.proxy_listen = Some(value(&mut args, &arg)?),
            "--config" => {
                value(&mut args, &arg)?;
            }
            "--max-users" => {
                config.max_users = value(&mut args, &arg)?.parse().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--max-users needs a number")
                })?
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Unknown option: {arg}"),
                ))
            }
        }
    }
    config.password = env::var("KELADIIRCD_PASSWORD")
        .ok()
        .filter(|s| !s.is_empty());
    config.validate()?;
    let listener = TcpListener::bind(&config.listen)?;
    eprintln!(
        "KeladiIRCd listening on {} as {}",
        listener.local_addr()?,
        config.name
    );
    serve(listener, config)
}

fn missing(option: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("Missing value for {option}"),
    )
}

fn value(args: &mut impl Iterator<Item = String>, option: &str) -> io::Result<String> {
    args.next().ok_or_else(|| missing(option))
}
