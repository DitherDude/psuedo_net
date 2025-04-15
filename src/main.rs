use magic_crypt::{MagicCryptTrait, new_magic_crypt};
use rand::Rng;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
//credit to https://www.youtube.com/watch?v=JiuouCJQzSQ for the tutorial

fn main() {
    //credit to Discord User u\866909828042850354 for port number
    let listener = TcpListener::bind("127.0.0.1:15496")
        .expect("[FATAL] Failed to bind to address. Is port in use?");
    println!("[INFO] Server listening on 127.0.0.1:15496");
    let mut sessionid = "".to_string();
    for _ in 0..7 {
        sessionid =
            sessionid + format!("{:X}", rand::rng().random_range(0..1E100 as u64)).as_str() + ":";
    }
    println!("[INFO] Session ID: {}", sessionid.trim_end_matches(':'));
    for stream in listener.incoming() {
        let sessionid = sessionid.trim_end_matches(':').to_string();
        match stream {
            Ok(stream) => {
                std::thread::spawn(move || handle_connection(stream, sessionid));
            }
            Err(e) => {
                eprintln!("[ERROR] Failed to establish connection with client: {}", e)
            }
        }
    }
}

fn handle_connection(mut stream: TcpStream, sessionid: String) {
    let mut buffer = [0; 1024];
    stream
        .read(&mut buffer)
        .expect("[ERROR] Received connection from client, but lost request.");
    let request = String::from_utf8_lossy(&buffer[..])
        .trim_end_matches('\0')
        .to_string();
    if request == "`".to_string() {
        stream
            .write(sessionid.as_bytes())
            .expect("[ERROR] Connected to client, but failed to send session ID.");
    } else {
        println!(
            "Received request \"{}\" from client!",
            decrypt(request, sessionid)
        );
        let response = "Connected Successfully".as_bytes();
        stream
            .write(response)
            .expect("[ERROR] Connected to client, but failed to send response.");
    }
}
fn decrypt(request: String, sessionid: String) -> String {
    let mc = new_magic_crypt!(sessionid, 256);
    return match mc.decrypt_base64_to_string(&request) {
        Ok(x) => x,
        Err(e) => e.to_string(),
    };
}
