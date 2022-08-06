use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Instant;

use clap::{self, Parser};
use rustls::{Certificate, ClientConfig, RootCertStore};
use rustls_native_certs::load_native_certs;

/// Debug HTTPS connection delays
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Hostname of server to connect to
    #[clap(index = 1)]
    hostname: String,
}

fn main() {
    let args = Args::parse();

    println!("Starting");
    let mut root_store = RootCertStore::empty();
    for cert in load_native_certs().expect("could not load platform certs") {
        root_store.add(&Certificate(cert.0)).unwrap();
    }
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let rc_config = Arc::new(config);
    let request = format!(
        "GET / HTTP/1.1\r\n\
             Host: {}\r\n\
             Connection: close\r\n\
             Accept-Encoding: identity\r\n\
             \r\n",
        args.hostname
    );

    let then = Instant::now();
    let addrs_iter = (args.hostname.as_str(), 443).to_socket_addrs().unwrap();
    println!("Got iter in {:?}", Instant::now() - then);
    let addrs: Vec<_> = addrs_iter.collect();
    println!("Got {:?} in {:?}", addrs, Instant::now() - then);

    for addr in addrs {
        let then = Instant::now();
        let mut socket = TcpStream::connect(addr).unwrap();
        // socket.set_nodelay(true);
        println!("Connected to {:?} in {:?}", addr, Instant::now() - then);
        let mut client = rustls::ClientConnection::new(
            rc_config.clone(),
            args.hostname.as_str().try_into().unwrap(),
        )
        .unwrap();

        let then = Instant::now();
        client.complete_io(&mut socket).unwrap();
        println!("TLS handshake completed in {:?}", Instant::now() - then);
        let ciphersuite = client.negotiated_cipher_suite().unwrap();
        println!("Current ciphersuite: {:?}", ciphersuite.suite());

        let then = Instant::now();
        let mut tls = rustls::Stream::new(&mut client, &mut socket);
        tls.write_all(request.as_bytes()).unwrap();
        let mut plaintext = Vec::new();
        tls.read_to_end(&mut plaintext).unwrap();
        println!(
            "Got {} response bytes in {:?}",
            plaintext.len(),
            Instant::now() - then
        );
        let text = std::str::from_utf8(&plaintext).unwrap();
        println!("First line: {}", text.lines().next().unwrap());
    }
    println!("Finished");
}
