use std::io::{self, Read, Write, prelude::*};
use std::net::TcpStream;
use magic_crypt::{new_magic_crypt, MagicCryptTrait};

fn main() {
    let stdin = io::stdin();
    let sessionid = sendrequest("`".to_string()).trim_end_matches('\0').to_string();
    // println!("Got Session ID {}", sessionid);
    for ln in stdin.lock().lines() {
        let line = ln.unwrap().to_string();
        let mc = new_magic_crypt!(&sessionid, 256);
        let encrypted_string = mc.encrypt_str_to_base64(&line);
        match sendrequest(encrypted_string).trim_end_matches('\0') {
            "Disconnected Successfully" => return,
            x => println!("{}", x.to_string()),
        }
    }
}

fn sendrequest(line: String) -> String {
    let mut stream = match TcpStream::connect("127.0.0.1:15496"){
        Ok(stream) => stream,
        Err(e) => panic!("Failed to connect to server: {}", e),
    };
    stream.write(line.as_bytes()).unwrap();
    let mut buffer = [0; 1024];
    stream.read(&mut buffer).unwrap();
    return String::from_utf8_lossy(&buffer[..]).to_string();
}
