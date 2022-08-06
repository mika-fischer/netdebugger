use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{self, Parser};
use rustls::{Certificate, ClientConfig, RootCertStore};
use rustls_native_certs::load_native_certs;

/// Debug HTTPS connection delays
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Hostname of server to connect to
    #[clap(value_parser)]
    hostname: String,

    /// Timeout for establishing of TCP connections
    #[clap(long, default_value_t = 5.0, value_parser)]
    connect_timeout: f32,
}

fn get_root_store() -> Result<RootCertStore, io::Error> {
    let mut root_store = RootCertStore::empty();
    for cert in load_native_certs()? {
        root_store.add(&Certificate(cert.0)).unwrap();
    }
    Ok(root_store)
}

fn get_client_config() -> Result<Arc<ClientConfig>, io::Error> {
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

fn main() {
    let args = Args::parse();

    println!("Resolving hostname {}...", &args.hostname);
    let then = Instant::now();
    let addrs_iter = (args.hostname.as_str(), 443).to_socket_addrs().unwrap();
    let addrs: Vec<_> = addrs_iter.collect();
    let resolve_time = Instant::now() - then;
    for addr in &addrs {
        println!(" Got {:?}", addr);
    }

    for addr in addrs {
        println!("Connecting to {:?}", &addr);
        let then = Instant::now();
        let mut socket =
            TcpStream::connect_timeout(&addr, Duration::from_secs_f32(args.connect_timeout))
                .unwrap();
        socket.set_nodelay(true).unwrap();
        let connect_time = Instant::now() - then;
        let mut client = rustls::ClientConnection::new(
            get_client_config().unwrap(),
            args.hostname.as_str().try_into().unwrap(),
        )
        .unwrap();

        let then = Instant::now();
        client.complete_io(&mut socket).unwrap();
        let handshake_time = Instant::now() - then;
        let ciphersuite = client.negotiated_cipher_suite().unwrap();
        let protocol_version = client.protocol_version();

        let request = get_request_for(&args.hostname);
        let mut tls = rustls::Stream::new(&mut client, &mut socket);
        let then = Instant::now();
        tls.write_all(request.as_bytes()).unwrap();
        let request_time = Instant::now() - then;
        let then = Instant::now();
        let mut plaintext = Vec::new();
        tls.read_to_end(&mut plaintext).unwrap();
        let response_time = Instant::now() - then;

        let idx = plaintext.iter().position(|c| *c != b'\r' && *c != b'\n');
        let status_bytes = &plaintext[..idx.unwrap_or(0)];
        let status_text = std::str::from_utf8(&status_bytes).unwrap();
        println!(" Response status: {}", status_text);
        println!(" Response length: {:?}", plaintext.len());
        println!(" TLS version:     {:?}", protocol_version);
        println!(" Cipher suite:    {:?}", ciphersuite);
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
}
