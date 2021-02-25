#![allow(irrefutable_let_patterns)]
#![allow(dead_code, unused_imports)]
#![allow(non_camel_case_types)]
#![deny(bare_trait_objects)]
#![warn(clippy::all)]
extern crate hyper;
use futures::stream::StreamExt;
use hyper::{Body, Client, Error, Method, Request, Response, StatusCode, Uri};
use serde::{Deserialize, Serialize};
use serde_json::Result;
use std::io::{prelude::*, BufRead, BufWriter, Read, Write};
use std::net::TcpStream;
use std::thread;

mod socks;

use oh_my_rust::*;
pub use socks::*;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum Addr {
    V4([u8; 4]),
    V6([u8; 16]),
    Domain(Box<[u8]>),
}

impl std::fmt::Display for Addr {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Addr::V4(x) => std::fmt::Display::fmt(&std::net::Ipv4Addr::from(*x), fmt),
            Addr::V6(x) => std::fmt::Display::fmt(&std::net::Ipv6Addr::from(*x), fmt),
            Addr::Domain(x) => {
                std::fmt::Display::fmt(std::str::from_utf8(x).msg(std::fmt::Error)?, fmt)
            }
        }
    }
}

#[derive(Deserialize, Serialize, Debug)]
struct HbServerResponse {
    r: Vec<u8>,
    msg: Vec<u8>,
    d: Vec<u8>,
    s: u16,
}
#[derive(Deserialize, Serialize, Debug, Clone)]
struct RemoteHostSpec {
    a: Addr,
    p: u16,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct RequestConnectSpec {
    d: RemoteHostSpec,
    i: Vec<u8>,
    s: usize,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct TcpStreamPacket {
    d: Vec<u8>,
}

fn send_reply(stream: &std::net::TcpStream) -> std::result::Result<&usize, std::io::ErrorKind> {
    let mut stream = stream;
    let local = stream.local_addr().unwrap();
    let local_addr = match local.ip() {
        std::net::IpAddr::V4(x) => Addr::V4(x.octets()),
        std::net::IpAddr::V6(x) => Addr::V6(x.octets()),
    };
    let local_port = local.port();

    let mut reply = Vec::with_capacity(22); // cover ipv4 and ipv5
    reply.extend_from_slice(&[5, 0, 0]);

    match local_addr {
        Addr::V4(x) => {
            reply.push(1);
            reply.extend_from_slice(&x);
        }
        Addr::V6(x) => {
            reply.push(4);
            reply.extend_from_slice(&x);
        }
        Addr::Domain(x) => {
            reply.push(3);
            reply.push(x.len() as u8);
            reply.extend_from_slice(&x);
        }
    }

    reply.push((local_port >> 8) as u8);
    reply.push(local_port as u8);

    match &stream.write(&reply) {
        Ok(_) => Ok(&5),
        Err(e) => Err(e.kind()),
    }
}

async fn json_decode_hyper_response<T: serde::de::DeserializeOwned>(
    mut response: hyper::Response<hyper::Body>,
) -> std::result::Result<T, Error> {
    let mut temp_holder: Vec<u8> = Vec::new();
    while let Some(d) = response.body_mut().next().await {
        temp_holder.extend_from_slice(&d.unwrap())
    }
    let output: T = serde_json::from_slice(&temp_holder).unwrap();
    Ok(output)
}

async fn create_remote_socket(
    url: &str,
    http_client: &hyper::Client<hyper::client::HttpConnector>,
) -> std::result::Result<hyper::Response<hyper::Body>, hyper::StatusCode> {
    match http_client
        .request(
            hyper::Request::builder()
                .method(Method::PUT)
                .uri(url)
                .header("User-Agent", "Socks5 Hbclient/0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
    {
        hyper::Result::Ok(r) => {
            match r.status() {
                StatusCode::CREATED => {
                    return Ok(r);
                }
                StatusCode::INTERNAL_SERVER_ERROR => {
                    let res_data_json: HbServerResponse =
                        json_decode_hyper_response(r).await.unwrap();

                    println!(
                        "Create Remote Socket Failed with Error: {}",
                        String::from_utf8(res_data_json.msg).unwrap()
                    );
                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }
                _ => return Err(StatusCode::INTERNAL_SERVER_ERROR),
            };
        }
        hyper::Result::Err(e) => {
            println!("Error: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
}

async fn connect_remote_socket(
    url: &str,
    http_client: &hyper::Client<hyper::client::HttpConnector>,
    remote_host: RequestConnectSpec,
    cookie: &hyper::http::HeaderValue,
) -> std::result::Result<hyper::Response<hyper::Body>, hyper::StatusCode> {
    match http_client
        .request(
            hyper::Request::builder()
                .method(Method::PATCH)
                .uri(url)
                .header("User-Agent", "Socks5 Hbclient/0.0.1")
                .header("Content-Type", "application/json")
                .header("Cookie", cookie)
                .body(Body::from(
                    serde_json::to_string(&remote_host).unwrap().into_bytes(),
                ))
                .unwrap(),
        )
        .await
    {
        hyper::Result::Ok(r) => {
            match r.status() {
                StatusCode::CREATED => {
                    return Ok(r);
                }
                StatusCode::INTERNAL_SERVER_ERROR => {
                    let res_data_json: HbServerResponse =
                        json_decode_hyper_response(r).await.unwrap();
                    println!(
                        "Connect Remote Socket Failed with Error: {}",
                        String::from_utf8(res_data_json.msg).unwrap()
                    );
                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }
                _ => return Err(StatusCode::INTERNAL_SERVER_ERROR),
            };
        }
        hyper::Result::Err(e) => {
            println!("Error: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
}

async fn read_remote_socket(
    url: &str,
    http_client: &hyper::Client<hyper::client::HttpConnector>,
    cookie: &hyper::http::HeaderValue,
) -> std::result::Result<HbServerResponse, hyper::StatusCode> {
    match http_client
        .request(
            hyper::Request::builder()
                .method(Method::GET)
                .uri(url)
                .header("User-Agent", "Socks5 Hbclient/0.0.1")
                .header("Content-Type", "application/json")
                .header("Cookie", cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
    {
        hyper::Result::Ok(r) => {
            match r.status() {
                StatusCode::OK => {
                    let mut res_data: Vec<u8> = vec![];
                    let mut r = r;
                    while let Some(d) = r.body_mut().next().await {
                        res_data.extend_from_slice(&d.unwrap());
                    }
                    let res_data_json: HbServerResponse =
                        serde_json::from_slice(&res_data).unwrap();
                    return Ok(res_data_json);
                }
                StatusCode::INTERNAL_SERVER_ERROR => {
                    let res_data_json: HbServerResponse =
                        json_decode_hyper_response(r).await.unwrap();
                    println!(
                        "Read Remote Socket Failed with Error: {}",
                        String::from_utf8(res_data_json.msg).unwrap()
                    );
                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }
                _ => return Err(StatusCode::INTERNAL_SERVER_ERROR),
            };
        }
        hyper::Result::Err(e) => {
            println!("Error: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
}

async fn write_remote_socket(
    url: &str,
    http_client: &hyper::Client<hyper::client::HttpConnector>,
    cookie: &hyper::http::HeaderValue,
    data_packet: TcpStreamPacket,
) -> std::result::Result<hyper::Response<hyper::Body>, hyper::StatusCode> {
    match http_client
        .request(
            hyper::Request::builder()
                .method(Method::POST)
                .uri(url)
                .header("User-Agent", "Socks5 Hbclient/0.0.1")
                .header("Content-Type", "application/json")
                .header("Cookie", cookie)
                .body(Body::from(
                    serde_json::to_string(&data_packet).unwrap().into_bytes(),
                ))
                .unwrap(),
        )
        .await
    {
        hyper::Result::Ok(r) => {
            match r.status() {
                StatusCode::OK => {
                    return Ok(r);
                }
                StatusCode::INTERNAL_SERVER_ERROR => {
                    let res_data_json: HbServerResponse =
                        json_decode_hyper_response(r).await.unwrap();
                    println!(
                        "Read Remote Socket Failed with Error: {}",
                        String::from_utf8(res_data_json.msg).unwrap()
                    );
                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }
                _ => return Err(StatusCode::INTERNAL_SERVER_ERROR),
            };
        }
        hyper::Result::Err(e) => {
            println!("Error: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
}

async fn remove_remote_socket(
    url: &str,
    http_client: &hyper::Client<hyper::client::HttpConnector>,
    cookie: &hyper::http::HeaderValue,
) -> std::result::Result<hyper::Response<hyper::Body>, hyper::StatusCode> {
    match http_client
        .request(
            hyper::Request::builder()
                .method(Method::DELETE)
                .uri(url)
                .header("User-Agent", "Socks5 Hbclient/0.0.1")
                .header("Content-Type", "application/json")
                .header("Cookie", cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
    {
        hyper::Result::Ok(r) => {
            match r.status() {
                StatusCode::OK => {
                    return Ok(r);
                }
                StatusCode::INTERNAL_SERVER_ERROR => {
                    let res_data_json: HbServerResponse =
                        json_decode_hyper_response(r).await.unwrap();
                    println!(
                        "Read Remote Socket Failed with Error: {}",
                        String::from_utf8(res_data_json.msg).unwrap()
                    );
                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }
                _ => return Err(StatusCode::INTERNAL_SERVER_ERROR),
            };
        }
        hyper::Result::Err(e) => {
            println!("Error: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
}

async fn read_client_stream(
    mut stream: &std::net::TcpStream,
) -> std::result::Result<Vec<u8>, std::io::ErrorKind> {
    const MSG_SIZE: usize = 256;
    let mut buffer: Vec<u8> = vec![];
    let mut temp_buffer = [0u8; MSG_SIZE];
    let zero_value: usize = 0;
    loop {
        match stream.read(&mut temp_buffer) {
            Ok(rx) => {
                if zero_value <= rx && rx <= temp_buffer.len() {
                    buffer.extend_from_slice(&temp_buffer[..rx]);
                    if rx < temp_buffer.len() {
                        break;
                    }
                } else {
                    break;
                }
            }
            Err(e) => {
                println!("Hbclient Error raised {} -> Attempt to continue", e);
                break;
            }
        }
    }
    Ok(buffer)
}

async fn write_client_stream(
    mut stream: &std::net::TcpStream,
    data: Vec<u8>,
) -> std::result::Result<(), std::io::ErrorKind> {
    match stream.write(&data) {
        Ok(_) => Ok(()),
        Err(e) => {
            println!("Hbclient Error writing client stream {}", e);
            Err(e.kind())
        }
    }
}

#[tokio::main]
async fn hbswg_pass(
    stream: TcpStream,
    raddr: Addr,
    port: u16,
    url: String,
    path: String,
    //) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
) {
    let mut hbswgurl = String::new();
    hbswgurl.push_str(&url[..]);
    hbswgurl.push_str(&path[..]);
    let client = hyper::Client::new();
    stream
        .set_read_timeout(Some(std::time::Duration::from_millis(1000)))
        .unwrap();
    //stream.set_nonblocking(true).unwrap();
    send_reply(&stream).unwrap();
    let mut initial_client_buffer: Vec<u8> = Vec::new();
    if let dt = read_client_stream(&stream).await.unwrap() {
        initial_client_buffer.extend_from_slice(&dt);
    }
    if let response_headers = create_remote_socket(&hbswgurl, &client).await.unwrap() {
        let cookie_session = response_headers.headers().get("Set-Cookie").unwrap();
        if let connect_response = connect_remote_socket(
            &hbswgurl,
            &client,
            RequestConnectSpec {
                d: RemoteHostSpec {
                    a: raddr.clone(),
                    p: port,
                },
                i: initial_client_buffer.clone(),
                s: initial_client_buffer.len(),
            },
            &cookie_session,
        )
        .await
        .unwrap()
        {
            let response_json: HbServerResponse =
                json_decode_hyper_response(connect_response).await.unwrap();
            if response_json.s > 0 {
                write_client_stream(&stream, response_json.d).await.unwrap();
            }
            let quit = false;
            loop {
                // avoid cpu exhaust
                std::thread::sleep(std::time::Duration::from_millis(1));
                if let buf = read_client_stream(&stream).await.unwrap() {
                    if !buf.is_empty() {
                        write_remote_socket(
                            &hbswgurl,
                            &client,
                            &cookie_session,
                            TcpStreamPacket { d: buf },
                        )
                        .await
                        .unwrap();
                        if let read_response =
                            read_remote_socket(&hbswgurl, &client, &cookie_session)
                                .await
                                .unwrap()
                        {
                            if read_response.s > 0 {
                                write_client_stream(&stream, read_response.d).await.unwrap();
                            }
                        }
                    }
                }
                if quit {
                    break;
                }
            }
        }
    }
}
