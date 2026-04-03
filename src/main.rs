use std::net::{SocketAddr, UdpSocket};
use std::thread;

use dnsntp::process_dns_request;

fn main() {
    let addr: SocketAddr = "0.0.0.0:53535".parse().expect("address");
    let socket = UdpSocket::bind(addr).expect("Listen failed");
    eprintln!("Listening on {addr}");

    let mut buf = [0u8; 512];
    loop {
        match socket.recv_from(&mut buf) {
            Ok((n, client_addr)) => {
                let payload = buf[..n].to_vec();
                let sock = match socket.try_clone() {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("clone error: {e}");
                        continue;
                    }
                };
                thread::spawn(move || handle_client(sock, payload, client_addr));
            }
            Err(e) => eprintln!("Read error: {e}"),
        }
    }
}

fn handle_client(conn: UdpSocket, data: Vec<u8>, client_addr: SocketAddr) {
    let (packet, reply) = match process_dns_request(&data) {
        Some(v) => v,
        None => {
            eprintln!("Ignored or invalid DNS request from {client_addr}");
            return;
        }
    };

    eprintln!(
        "{client_addr} requests {packet:?} reply {} octets",
        reply.len()
    );

    if let Err(e) = conn.send_to(&reply, client_addr) {
        eprintln!("Write error: {e}");
    }
}
