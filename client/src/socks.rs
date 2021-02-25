extern crate hyper;
use super::*;
use futures::stream::StreamExt;
use hyper::{Body, Client, Method, Request, Uri};
use oh_my_rust::*;
use serde::{Deserialize, Serialize};
use serde_json::Result;
use std::io::{prelude::*, BufRead, BufWriter, Error, Read, Write};
use std::net::{TcpListener, TcpStream};

macro_rules! read_exact {
    ($stream: expr, $array: expr) => {{
        let mut x = $array;
        $stream.read_exact(&mut x).map(|_| x)
    }};
}

macro_rules! close_on_error {
    ($ex: expr) => {{
        match $ex {
            Ok(x) => x,
            Err(e) => return warn!("{}", e),
        }
    }};
}

pub struct Socks5Server {
    port: u16,
    url: String,
    path: String,
}

impl Socks5Server {
    pub fn new(port: u16, url: String, path: String) -> Socks5Server {
        Socks5Server { port, url, path }
    }

    pub fn listen(&self) -> ! {
        let socket =
            TcpListener::bind(format!("0.0.0.0:{}", self.port)).expect("Address already in use");
        info!(
            "Socks Bridge Client start listening at 0.0.0.0:{}",
            self.port
        );

        for stream in socket.incoming() {
            let url = self.url.clone().into_bytes();
            let path = self.path.clone().into_bytes();
            let stream = stream.unwrap();
            std::thread::spawn(move || {
                close_on_error!(initialize(&mut &stream));
                let (addr, port) = close_on_error!(read_request(&mut &stream));
                hbswg_pass(
                    stream,
                    addr,
                    port,
                    String::from_utf8(url).unwrap(),
                    String::from_utf8(path).unwrap(),
                );
            });
        }

        unreachable!()
    }
}

fn initialize(stream: &mut (impl ReadExt + Write)) -> std::result::Result<(), String> {
    let header = read_exact!(stream, [0, 0]).msg("read initial bits failed")?;

    if header[0] != 5 {
        let hint = "if the version is 71, the the software probabily used it as an HTTP proxy";
        return Err(format!(
            "unsupported socks version {}. Hint: {}",
            header[0], hint
        ));
    }

    let list: Vec<u8> = stream
        .read_exact_alloc(header[1] as usize)
        .msg("read methods failed")?;

    if !list.contains(&0) {
        stream.write(&[5, 0xff]).msg("write response failed")?;
        return Err("client do not support NO AUTH method".to_string());
    }

    stream.write(&[5, 0]).msg("write response failed")?;
    Ok(())
}

fn read_request(stream: &mut (impl ReadExt + Write)) -> std::result::Result<(Addr, u16), String> {
    let [ver, cmd, _rev, atyp] = read_exact!(stream, [0; 4]).msg("read request header failed")?;

    if ver != 5 {
        return Err(format!("unsupported socks version {}", ver));
    }

    if cmd != 1 {
        return Err(format!("unsupported command type {}", cmd));
    }

    let addr = match atyp {
        0x01 => Addr::V4(read_exact!(stream, [0; 4]).msg("read v4 address failed")?),
        0x04 => Addr::V6(read_exact!(stream, [0; 16]).msg("read v6 address failed")?),
        0x03 => {
            let len = read_exact!(stream, [0]).msg("read domain length failed")?[0];
            Addr::Domain(
                stream
                    .read_exact_alloc(len as usize)
                    .msg("read domain failed")?
                    .into_boxed_slice(),
            )
        }
        _ => return Err("Unknown ATYP".to_string()),
    };

    let port = read_exact!(stream, [0; 2]).msg("read port failed")?;
    let port = (port[0] as u16) << 8 | port[1] as u16;

    Ok((addr, port))
}
