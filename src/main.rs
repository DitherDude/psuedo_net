use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

//credit to https://www.youtube.com/watch?v=JiuouCJQzSQ for the tutorial

fn main() {
    //credit to Discord User u\866909828042850354 for port number
    let listener = TcpListener::bind("127.0.0.1:15496")
        .expect("[FATAL] Failed to bind to address. Is port in use?");
    println!("[INFO] Server listening on 127.0.0.1:15496.");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                std::thread::spawn(|| handle_connection(stream));
            }
            Err(e) => {
                eprintln!("[ERROR] Failed to establish connection with client: {}", e)
            }
        }
    }
}

fn handle_connection(mut stream: TcpStream) {
    let mut buffer = [0; 1024];
    stream
        .read(&mut buffer)
        .expect("[ERROR] Received connection from client, but lost request.");
    let request = String::from_utf8_lossy(&buffer[..]);
    println!("Received request \"{}\" from client!", request);
    let response = "Connected Successfully".as_bytes();
    stream
        .write(response)
        .expect("[ERROR] Connected to client, but failed to send response.");
}
