use base64::{Engine, engine::general_purpose};
use magic_crypt::{MagicCryptTrait, new_magic_crypt};
use p256::{EncodedPoint, PublicKey, ecdh::EphemeralSecret};
use rand::rngs::OsRng;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey, pkcs8::DecodePublicKey};
use std::env;
use std::io::{self, Read, Write, prelude::*};
use std::net::TcpStream;
use std::process;

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
        None => {
            let mut tmpid = send_request("`".to_string())
                .trim_end_matches('\0')
                .to_string();
            if tmpid == "err" {
                tmpid = login();
            }
            tmpid
        }
    };
    match sessionid.as_str() {
        "offline" => {
            eprintln!("Server unreachable.");
            return;
        }
        "err" => {
            eprintln!("Server expects a preexisting session ID, and login failed.");
            return;
        }
        _ => (),
    }
    println!(
        "{}",
        handle_request(
            send_request(
                "b".to_string()
                    + &new_magic_crypt!(&sessionid, 256).encrypt_str_to_base64("verify")
            ),
            sessionid.clone()
        )
    );
    let stdin = io::stdin();
    for ln in stdin.lock().lines() {
        let line = ln.unwrap().to_string();
        match line.as_str() {
            _ => {
                println!(
                    "{}",
                    handle_request(
                        send_request(
                            "b".to_string()
                                + &new_magic_crypt!(&sessionid, 256).encrypt_str_to_base64(&line)
                        ),
                        sessionid.clone()
                    )
                );
            }
        }
    }
}

fn login() -> String {
    let request_rsa = std::thread::spawn(move || {
        let data: String;
        match TcpStream::connect("127.0.0.1:15496") {
            Ok(mut stream) => {
                let client_secret = EphemeralSecret::random(&mut OsRng);
                let client_pk_bytes = EncodedPoint::from(client_secret.public_key());
                stream
                    .write(&["$".as_bytes(), client_pk_bytes.as_bytes()].concat())
                    .unwrap();
                let mut buffer = [0; 1024];
                loop {
                    match stream.read(&mut buffer) {
                        Ok(x) => {
                            if x == 0 {
                                continue;
                            }
                            let response = String::from_utf8_lossy(&buffer[..])
                                .trim_end_matches('\0')
                                .to_string();
                            if response == "err" {
                                println!(
                                    "[ERROR] Server expects a preexisting session ID, and login failed."
                                );
                                process::exit(1);
                            } else {
                                break;
                            }
                        }
                        Err(_) => {
                            println!("[ERROR] Server unreachable.");
                            process::exit(1);
                        }
                    }
                }
                let response = String::from_utf8_lossy(&buffer[..])
                    .trim_end_matches('\0')
                    .to_string();
                let (server_pk_bytes_b64, encrypted_rsa_key) = response.split_once(':').unwrap();
                let server_pk_bytes = general_purpose::STANDARD
                    .decode(server_pk_bytes_b64)
                    .unwrap();
                let server_public = PublicKey::from_sec1_bytes(server_pk_bytes.as_ref()).unwrap();
                let client_shared = client_secret.diffie_hellman(&server_public);
                data = new_magic_crypt!(client_shared.raw_secret_bytes(), 256)
                    .decrypt_base64_to_string(encrypted_rsa_key)
                    .unwrap();
            }
            Err(_) => {
                data = "offline".to_string();
            }
        };
        data
    });
    let stdin = io::stdin();
    print!("Username: ");
    io::stdout().flush().unwrap();
    let mut username = String::new();
    stdin.lock().read_line(&mut username).unwrap();
    let username = username.trim().to_string();
    print!("Password: ");
    io::stdout().flush().unwrap();
    let mut password = String::new();
    stdin.lock().read_line(&mut password).unwrap();
    println!("\x1B[1A\x1B[2KPassword:");
    let password = password.trim().to_string();
    print!("Waiting for server to send RSA key...");
    io::stdout().flush().unwrap();
    let rsa_key = request_rsa.join().unwrap().replace("*", "\n");
    println!("RSA key received.");
    let cleartext = username + ":" + &password;
    let mut rng = rand::rngs::OsRng;
    let public_key = RsaPublicKey::from_public_key_pem(&rsa_key.as_str()).unwrap();
    let cyphertext = public_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, cleartext.as_bytes())
        .unwrap();
    let sessionid = send_request("r".to_string() + &general_purpose::STANDARD.encode(cyphertext))
        .trim_end_matches('\0')
        .to_string();
    if sessionid == "err" {
        return "err".to_string();
    }
    let mc = new_magic_crypt!(&password, 256);
    return mc.decrypt_base64_to_string(&sessionid).unwrap();
}

fn send_request(line: String) -> String {
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

fn handle_request(mut request: String, sessionid: String) -> String {
    let response: String;
    request = request.trim_end_matches('\0').to_string();
    let mc = new_magic_crypt!(sessionid.clone(), 256);
    request = match mc.decrypt_base64_to_string(&request) {
        Ok(x) => x,
        Err(_) => request.clone(),
    };
    match request.as_str() {
        "Invalid Session ID" => {
            eprintln!(
                "Server could not verify the integrity of this connection, and thus terminated it."
            );
            process::exit(0);
        }
        "Disconnected Successfully" => {
            eprintln!("Server has terminated the connection.");
            process::exit(0);
        }
        "offline" => {
            eprintln!("Server unreachable.");
            process::exit(0);
        }
        "Connected Successfully" => {
            response = "Server successfully handled request.".to_string();
        }
        "err" => {
            response = "Invalid request! Server could not process request.".to_string();
        }
        x => response = x.to_string(),
    }
    return response;
}
