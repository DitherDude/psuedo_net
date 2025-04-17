use base64::{Engine, engine::general_purpose};
//use ecdh::SharedSecret;
use magic_crypt::{MagicCryptTrait, new_magic_crypt};
use p256::{EncodedPoint, PublicKey, ecdh::EphemeralSecret};
use rand::rngs::OsRng;
use rand_new::rngs::StdRng;
use rand_new::{SeedableRng, TryRngCore};
use rsa::{
    Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
    pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey},
};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

//credit to https://www.youtube.com/watch?v=JiuouCJQzSQ for the tutorial

fn main() {
    //credit to Discord User u\866909828042850354 for port number
    let listener = TcpListener::bind("127.0.0.1:15496")
        .expect("[FATAL] Failed to bind to address. Is port in use?");
    println!("[INFO] Server listening on 127.0.0.1:15496");
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
    let mut response = String::from_utf8_lossy(&buffer[..])
        .trim_end_matches('\0')
        .to_string();
    let identifier = response.chars().nth(0).unwrap();
    response = response
        .char_indices()
        .nth(1)
        .and_then(|(i, _)| response.get(i..))
        .unwrap_or("")
        .to_string();
    match identifier {
        '`' => {
            gen_sessionid(clientid);
            stream
                .write("err".as_bytes())
                .expect("[ERROR] Connected to client, but failed to send session ID.");
        }
        '$' => {
            let rsa_pub_key = std::thread::spawn(move || gen_rsa_key(clientid));
            let server_secret = EphemeralSecret::random(&mut OsRng);
            let server_pk_bytes = EncodedPoint::from(server_secret.public_key());
            let client_public = PublicKey::from_sec1_bytes(
                &buffer[1..]
                    .iter()
                    .rev()
                    .skip_while(|&x| *x == u8::default())
                    .collect::<Vec<&u8>>()
                    .into_iter()
                    .rev()
                    .copied()
                    .collect::<Vec<u8>>(),
            )
            .unwrap();
            let server_shared = server_secret.diffie_hellman(&client_public);
            let data = general_purpose::STANDARD.encode(server_pk_bytes.as_bytes())
                + ":"
                + &new_magic_crypt!(server_shared.raw_secret_bytes(), 256)
                    .encrypt_str_to_base64(rsa_pub_key.join().unwrap().to_string());
            stream
                .write(data.as_bytes())
                .expect("[ERROR] Connected to client, but failed to send H-D public key.");
        }
        x => {
            let data: String;
            match x {
                'b' => {
                    data = decrypt(response, get_sessionid(clientid.clone()));
                }
                'r' => {
                    let rsa_key = get_rsa_key(clientid.clone());
                    let private_key = RsaPrivateKey::from_pkcs8_pem(&rsa_key).unwrap();
                    let cyphertext_bytes = general_purpose::STANDARD.decode(response).unwrap();
                    let cleartext_bytes = private_key
                        .decrypt(Pkcs1v15Encrypt, &cyphertext_bytes)
                        .unwrap();
                    data = String::from_utf8(cleartext_bytes).unwrap();
                    if data == "admin:Passw0rd" {
                        println!("[INFO] Admin {} connected.", clientid);
                        let mc = new_magic_crypt!("Passw0rd", 256);
                        let mut sessionid = get_sessionid(clientid.clone());
                        if sessionid == "err" {
                            sessionid = gen_sessionid(clientid.clone());
                        }
                        let encrypted_string = mc.encrypt_str_to_base64(sessionid);
                        stream.write(encrypted_string.as_bytes()).expect(
                            "[ERROR] Connected to client, but failed to send encrypted session ID.",
                        );
                    } else {
                        stream
                            .write("err".as_bytes())
                            .expect("[ERROR] Connected to client, but failed to send response.");
                    }
                }
                //'d' => {}
                _ => {
                    data = "err".to_string();
                }
            }
            match data.as_str() {
                "disconnect" => {
                    send_encrypted_response(
                        &stream,
                        "Disconnected Successfully",
                        "[ERROR] Connected to client, but failed to send response.",
                    );
                    remove_client(clientid.clone());
                    println!("[INFO] Client {} forogtten.", clientid);
                    return;
                }
                "foreign" => {
                    stream
                        .write("Invalid Session ID".as_bytes())
                        .expect("[ERROR] Connected to client, but failed to send response.");
                    println!("[INFO] Unrecognized client {} disconnected.", clientid);
                    return;
                }
                _ => {
                    let protocol = match x {
                        'b' => "Salted Base64",
                        'r' => "RSA-3072",
                        'd' => "Diffie-Hellman",
                        _ => "unknown",
                    };
                    println!(
                        "[INFO] Received \"{}\" from {} via {}!",
                        data, clientid, protocol
                    );
                }
            }

            let response = "Connected Successfully";
            send_encrypted_response(
                &stream,
                response,
                "[ERROR] Connected to client, but failed to send response.",
            );
        }
    }
}
fn decrypt(request: String, sessionid: String) -> String {
    let mc = new_magic_crypt!(sessionid.clone(), 256);
    return match mc.decrypt_base64_to_string(&request) {
        Ok(x) => x,
        Err(_) => "foreign".to_string(),
    };
}

fn send_encrypted_response(mut stream: &TcpStream, response: &str, expect: &str) {
    let sessionid = get_sessionid(stream.peer_addr().unwrap().ip().to_string());
    let mc = new_magic_crypt!(sessionid.clone(), 256);
    let encrypted_string = mc.encrypt_str_to_base64(response);
    stream.write(encrypted_string.as_bytes()).expect(&expect);
}

fn get_sessionid(client: String) -> String {
    if !std::fs::metadata("sessionid.txt").is_ok() {
        std::fs::File::create("sessionid.txt").unwrap();
    }
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
    return "err".to_string();
}

fn gen_sessionid(client: String) -> String {
    if !std::fs::metadata("sessionid.txt").is_ok() {
        std::fs::File::create("sessionid.txt").unwrap();
    }
    let mut file = std::fs::File::open("sessionid.txt").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    for line in contents.lines() {
        if line.starts_with(&client) {
            return "err".to_string();
        }
    }
    let mut sessionid = "".to_string();
    for _ in 0..7 {
        sessionid = sessionid
            + format!(
                "{:X}",
                StdRng::try_next_u64(&mut StdRng::from_os_rng()).unwrap()
            )
            .as_str()
            + ":";
    }
    let sessionid = sessionid.trim_end_matches(':').to_string();
    contents = contents + "\n" + &client + " " + sessionid.as_str();
    file = std::fs::File::create("sessionid.txt").unwrap();
    file.write_all(contents.replace("\n\n", "\n").as_bytes())
        .unwrap();
    println!("[INFO] New client {} connected.", client);
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

fn get_rsa_key(client: String) -> String {
    if !std::fs::metadata("rsakeys.txt").is_ok() {
        std::fs::File::create("rsakeys.txt").unwrap();
    }
    let mut file = std::fs::File::open("rsakeys.txt").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    for line in contents.lines() {
        if line.starts_with(&client) {
            return line
                .to_string()
                .trim_start_matches(&client)
                .trim_start()
                .replace("*", "\n")
                .to_string();
        }
    }
    return "err".to_string();
}

fn gen_rsa_key(client: String) -> String {
    println!("[INFO] Generating RSA key for client {}...", client);
    if !std::fs::metadata("rsakeys.txt").is_ok() {
        std::fs::File::create("rsakeys.txt").unwrap();
    }
    let mut file = std::fs::File::open("rsakeys.txt").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    for line in contents.clone().lines() {
        if line.starts_with(&client) {
            contents = contents.replace(line, "");
        }
    }
    let mut rng = rand::rngs::OsRng;
    let bits = 3072;
    let private_key = RsaPrivateKey::new(&mut rng, bits).unwrap();
    let public_key = RsaPublicKey::from(&private_key);
    let priv_str = &private_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap()
        .replace("\n", "*");
    let pub_str = public_key
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap()
        .replace("\n", "*");
    contents = contents + "\n" + &client + " " + priv_str.as_str();
    file = std::fs::File::create("rsakeys.txt").unwrap();
    file.write_all(contents.replace("\n\n", "\n").as_bytes())
        .unwrap();
    println!("[INFO] RSA key generated for client {}.", client);
    return pub_str;
}
