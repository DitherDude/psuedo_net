use std::io;
use std::io::prelude::*;
use std::io::{Read, Write};
use std::net::TcpStream;
use magic_crypt::{new_magic_crypt, MagicCryptTrait};

fn main() {
    let stdin = io::stdin();
    let sessionid = sendrequest("`".to_string()).trim_end_matches('\0').to_string();
    println!("Got Session ID {}", sessionid);
    for ln in stdin.lock().lines() {
        let mut line = ln.unwrap().to_string();
        let mc = new_magic_crypt!(&sessionid, 256);
        let encrypted_string = mc.encrypt_str_to_base64(&line);
        println!("{}", sendrequest(encrypted_string));
    }
}

fn sendrequest(line: String) -> String {
    let mut stream = match TcpStream::connect("127.0.0.1:15496"){
        Ok(stream) => stream,
        Err(e) => panic!("[ERROR] Failed to connect to server: {}", e),
    };
    stream.write(line.as_bytes()).unwrap();
    let mut buffer = [0; 1024];
    stream.read(&mut buffer).unwrap();
    return String::from_utf8_lossy(&buffer[..]).to_string();
}
