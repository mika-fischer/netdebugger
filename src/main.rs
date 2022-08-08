#![warn(clippy::all, clippy::pedantic, clippy::nursery)]

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{self, Parser};
use color_eyre::eyre;
use rustls::{Certificate, ClientConfig, ClientConnection, RootCertStore, Stream};
use rustls_native_certs::load_native_certs;

/// Debug HTTPS connection delays
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Hostname of server to connect to
    #[clap(value_parser)]
    hostname: String,

    /// Timeout for establishing of TCP connections
    #[clap(long, default_value_t = Duration::from_secs(5).into(), value_parser)]
    connect_timeout: humantime::Duration,
}

fn get_root_store() -> Result<RootCertStore, eyre::Report> {
    let mut root_store = RootCertStore::empty();
    for cert in load_native_certs()? {
        root_store.add(&Certificate(cert.0))?;
    }
    Ok(root_store)
}

fn get_client_config() -> Result<Arc<ClientConfig>, eyre::Report> {
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(get_root_store()?)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

fn get_request_for(hostname: &str) -> String {
    format!(
        "GET / HTTP/1.1\r\n\
             Host: {}\r\n\
             Connection: close\r\n\
             Accept-Encoding: identity\r\n\
             \r\n",
        hostname
    )
}

fn main() -> Result<(), eyre::Report> {
    color_eyre::install()?;

    let args = Args::parse();

    println!("Resolving hostname {}...", &args.hostname);
    let then = Instant::now();
    let addrs_iter = (args.hostname.as_str(), 443).to_socket_addrs()?;
    let addrs: Vec<_> = addrs_iter.collect();
    let resolve_time = Instant::now() - then;
    for addr in &addrs {
        println!(" Got {:?}", addr);
    }

    for addr in addrs {
        println!("Connecting to {:?}", &addr);

        let then = Instant::now();
        let mut socket = TcpStream::connect_timeout(&addr, args.connect_timeout.into())?;
        let connect_time = Instant::now() - then;

        let then = Instant::now();
        let client_config = get_client_config()?;
        let server_name = args.hostname.as_str().try_into()?;
        let mut client = ClientConnection::new(client_config, server_name)?;
        client.complete_io(&mut socket)?;
        let handshake_time = Instant::now() - then;

        let then = Instant::now();
        let mut tls = Stream::new(&mut client, &mut socket);
        tls.write_all(get_request_for(&args.hostname).as_bytes())?;
        let request_time = Instant::now() - then;

        let then = Instant::now();
        let mut plaintext = Vec::new();
        tls.read_to_end(&mut plaintext)?;
        let response_time = Instant::now() - then;

        let idx = plaintext.iter().position(|c| *c == b'\r' || *c == b'\n');
        let status_bytes = &plaintext[..idx.unwrap_or(0)];
        let status_text = std::str::from_utf8(status_bytes)?;
        let version_string = client
            .protocol_version()
            .map_or_else(|| "<null>".to_string(), |v| format!("{:?}", v));
        let ciphersuite_string = client
            .negotiated_cipher_suite()
            .map_or_else(|| "<null>".to_string(), |v| format!("{:?}", v));
        println!(" Response status: {}", status_text);
        println!(" Response length: {:?}", plaintext.len());
        println!(" TLS version:     {:?}", version_string);
        println!(" Cipher suite:    {:?}", ciphersuite_string);
        let total_time =
            resolve_time + connect_time + handshake_time + request_time + response_time;
        println!(" Timings:");
        println!("  resolve:   {:?}", resolve_time);
        println!("  connect:   {:?}", connect_time);
        println!("  handshake: {:?}", handshake_time);
        println!("  request:   {:?}", request_time);
        println!("  response:  {:?}", response_time);
        println!("  total:     {:?}", total_time);
    }
    Ok(())
}
