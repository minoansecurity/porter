mod commands;

pub const GREEN: &str = "\x1b[32m";
pub const RED: &str = "\x1b[31m";
pub const YELLOW: &str = "\x1b[33m";
pub const DIM: &str = "\x1b[2m";
pub const BOLD: &str = "\x1b[1m";
pub const RESET: &str = "\x1b[0m";

pub fn is_unprivileged() -> bool {
    std::process::Command::new("id").arg("-u").output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() != "0")
        .unwrap_or(true)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    match args.first().map(|s| s.as_str()) {
        None => commands::list::run(),

        #[cfg(feature = "watch")]
        Some("watch") => commands::watch::run(),

        #[cfg(feature = "kill")]
        Some("kill") => commands::kill::run(&args[1..]),

        Some("--version" | "-V") => println!("porter {}", env!("CARGO_PKG_VERSION")),
        Some(unknown) => {
            eprintln!("unknown command: {unknown}\nUsage: porter [watch|kill <port>]");
            std::process::exit(1);
        }
    }
}
