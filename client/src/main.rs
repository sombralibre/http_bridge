extern crate getopts;
use getopts::Options;
use hbslib::*;

const USAGE: &'static str = "
Usage: hbclient -p [--port] 1986 -u [--url]  http://localhost:8080/hbserver.php -r [--rpath] /hbserver/stream/json
";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.len() {
        0 | 1 => {
            hbs(&Socks5Server::new(
                1986,
                "http://localhost:8080/hbserver.php".to_owned(),
                "/hbswg/stream/json".to_owned(),
            ));
        }
        _ => {
            let mut opts = Options::new();
            let help = |f: String| {
                eprint!("{}", f);
            };
            opts.optopt("p", "port", "Socks5 listener port", "<1986>");
            opts.optopt(
                "u",
                "url",
                "Url of the HBSWG.",
                "<http://localhost:8080/hbserver.php>",
            );
            opts.optopt(
                "r",
                "rpath",
                "Rest path for the request",
                "</hbserver/stream/json>",
            );
            opts.optopt("h", "help", "Print input options", "HELP");
            let matches = match opts.parse(&args[0..]) {
                Ok(m) => m,
                Err(f) => {
                    help(opts.usage(USAGE));
                    panic!(f.to_string());
                }
            };
            if matches.opt_present("h") {
                help(opts.usage(USAGE));
            }
            let port = matches.opt_get_default("p", 1986).unwrap();
            let url = matches
                .opt_get_default("u", "http://localhost:8080/hbserver.php".to_owned())
                .unwrap();
            let rpath = matches
                .opt_get_default("r", "/hbserver/stream/json".to_owned())
                .unwrap();
            hbs(&Socks5Server::new(port, url, rpath));
        }
    }
}

/* fn is_normal_close(e: &std::io::Error) -> bool {
    match e.kind() {
        std::io::ErrorKind::BrokenPipe
        | std::io::ErrorKind::UnexpectedEof
        | std::io::ErrorKind::ConnectionReset => true,
        _ => false,
    }
} */

fn hbs(server: &Socks5Server) {
    server.listen()
}
