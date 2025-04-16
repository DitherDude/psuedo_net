use magic_crypt::{MagicCryptTrait, new_magic_crypt};
use std::env;
use std::io::{self, Read, Write, prelude::*};
use std::net::TcpStream;

fn main() {
    let args: Vec<String> = env::args().collect();
    let sessionid = match args.get(1) {
        Some(x) => {
            let mut contents = String::new();
            match std::fs::File::open(x) {
                Ok(mut file) => {
                    file.read_to_string(&mut contents).unwrap();
                }
                Err(_) => {
                    eprintln!("File not found");
                    return;
                }
            }
            contents.to_string()
        }
        None => sendrequest("`".to_string())
            .trim_end_matches('\0')
            .to_string(),
    };
    let stdin = io::stdin();
    match sessionid.as_str() {
        "offline" => {
            eprintln!("Server unreachable.");
            return;
        }
        "err" => {
            eprintln!("Server expects a preexisting session ID.");
            return;
        }
        _ => (),
    }
    match sendrequest(
        "b".to_string() + &new_magic_crypt!(&sessionid, 256).encrypt_str_to_base64("verify"),
    )
    .trim_end_matches('\0')
    {
        "Invalid Session ID" => {
            eprintln!(
                "Server could not verify the integrity of this connection, and thus terminated it."
            );
            return;
        }
        "offline" => {
            eprintln!("Server unreachable.");
            return;
        }
        _ => {
            println!("Connected to server",);
        }
    }
    for ln in stdin.lock().lines() {
        //let line = "b".to_string() + &ln.unwrap();//.to_string();
        let line = ln.unwrap().to_string();
        let mc = new_magic_crypt!(&sessionid, 256);
        let encrypted_string = mc.encrypt_str_to_base64(&line);
        match sendrequest("b".to_string() + &encrypted_string).trim_end_matches('\0') {
            "Disconnected Successfully" => {
                println!("Server has terminated the connection.");
                return;
            }
            "offline" => {
                eprintln!("Server unreachable.");
                return;
            }
            "Connected Successfully" => {
                println!("Server successfully handled request.");
            }
            x => println!("{}", x.to_string()),
        }
    }
}

fn sendrequest(mut line: String) -> String {
    match TcpStream::connect("127.0.0.1:15496") {
        Ok(mut stream) => {
            stream.write(line.as_bytes()).unwrap();
            let mut buffer = [0; 1024];
            stream.read(&mut buffer).unwrap();
            return String::from_utf8_lossy(&buffer[..]).to_string();
        }
        Err(_) => {
            return "offline".to_string();
        }
    };
}
