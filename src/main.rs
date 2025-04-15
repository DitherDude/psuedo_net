use magic_crypt::{MagicCryptTrait, new_magic_crypt};
use rand::rngs::StdRng;
use rand::{SeedableRng, TryRngCore};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
//credit to https://www.youtube.com/watch?v=JiuouCJQzSQ for the tutorial

fn main() {
    if !std::fs::metadata("sessionid.txt").is_ok() {
        std::fs::File::create("sessionid.txt").unwrap();
    }
    //credit to Discord User u\866909828042850354 for port number
    let listener = TcpListener::bind("127.0.0.1:15496")
        .expect("[FATAL] Failed to bind to address. Is port in use?");
    println!("[INFO] Server listening on 127.0.0.1:15496");
    //
    //println!("[INFO] Session ID: {}", sessionid.trim_end_matches(':'));
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                std::thread::spawn(move || handle_connection(stream));
            }
            Err(e) => {
                eprintln!("[ERROR] Failed to establish connection with client: {}", e)
            }
        }
    }
}

fn handle_connection(mut stream: TcpStream) {
    let clientid = stream.peer_addr().unwrap().ip().to_string();
    let mut buffer = [0; 1024];
    stream
        .read(&mut buffer)
        .expect("[ERROR] Received connection from client, but lost request.");
    match String::from_utf8_lossy(&buffer[..]).trim_end_matches('\0') {
        "`" => {
            stream
                .write(get_sessionid(clientid).as_bytes())
                .expect("[ERROR] Connected to client, but failed to send session ID.");
        }
        x => {
            match decrypt(x.to_string(), get_sessionid(clientid.clone())).as_str() {
                "disconnect" => {
                    remove_client(clientid.clone());
                    stream
                        .write("Disconnected Successfully".as_bytes())
                        .expect("[ERROR] Connected to client, but failed to send response.");
                    println!("[INFO] Client {} forogtten.", clientid);
                }
                req => {
                    println!("Received request \"{}\" from client!", req);
                }
            }

            let response = "Connected Successfully".as_bytes();
            stream
                .write(response)
                .expect("[ERROR] Connected to client, but failed to send response.");
        }
    }
}
fn decrypt(request: String, sessionid: String) -> String {
    let mc = new_magic_crypt!(sessionid, 256);
    return match mc.decrypt_base64_to_string(&request) {
        Ok(x) => x,
        Err(e) => e.to_string(),
    };
}

fn get_sessionid(client: String) -> String {
    let mut file = std::fs::File::open("sessionid.txt").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    for line in contents.lines() {
        if line.starts_with(&client) {
            return line
                .to_string()
                .trim_start_matches(&client)
                .trim_start()
                .to_string();
        }
    }
    let mut sessionid = "".to_string();
    for _ in 0..7 {
        sessionid = sessionid
            //+ format!("{:X}", OsRng.try_next_u64().unwrap()).as_str()//.random_range(0..1E100 as u64)).as_str()
            + format!("{:X}", StdRng::try_next_u64(&mut StdRng::from_os_rng()).unwrap()).as_str()//.random_range(0..1E100 as u64)).as_str()
            + ":";
    }
    let sessionid = sessionid.trim_end_matches(':').to_string();
    contents = contents + "\n" + &client + " " + &sessionid;
    file = std::fs::File::create("sessionid.txt").unwrap();
    file.write_all(contents.as_bytes()).unwrap();
    println!("[INFO] New client {} connected.", client);
    // println!("[INFO] Session ID: {}", sessionid);
    return sessionid;
}

fn remove_client(client: String) {
    let mut file = std::fs::File::open("sessionid.txt").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    let mut new_contents = "".to_string();
    for line in contents.lines() {
        if !line.starts_with(&client) {
            new_contents = new_contents + line + "\n";
        }
    }
    file = std::fs::File::create("sessionid.txt").unwrap();
    file.write_all(new_contents.trim().as_bytes()).unwrap();
}
