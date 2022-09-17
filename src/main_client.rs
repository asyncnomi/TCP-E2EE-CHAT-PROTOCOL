use std::io::prelude::*;
use std::io::{stdin, stdout};
use std::net::TcpStream;
use rsa::{PublicKey, RsaPrivateKey, RsaPublicKey, PaddingScheme, PublicKeyParts, BigUint};
use concat_arrays::concat_arrays;
use rpassword;
use std::thread;
use linefeed::{Interface, ReadResult};
use lazy_static::lazy_static;
use sha2::{Sha384};

const PYLD_LENGTH: usize = 512;
const OAEP_PAD: usize = 98; // i.e sha384
const NAME_LENGTH: usize = 112; // e.g 28 unicode char
const PWD_LENGTH: usize = 128; // e.g 28 unicode char
const TOKEN_LENGTH: usize = 8;

lazy_static! {
    static ref INTERFACE: Interface<linefeed::terminal::DefaultTerminal> = Interface::new("msg").unwrap();
}

fn main() {
    let mut stream = match TcpStream::connect("127.0.0.1:2001") {
        Ok(stream) => {
            println!("TCP connection established");
            stream
        },
        Err(err) => panic!("Could not connect to the server: {}.", err)
    };

    INTERFACE.set_prompt("> ").unwrap();

    // Init connection
    println!("Creating new RSA keys...");
    let mut rng = rand::thread_rng();
    let bits = PYLD_LENGTH*8;
    let client_private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let client_public_key = RsaPublicKey::from(&client_private_key);
    let client_public_key_n_bytes: [u8; PYLD_LENGTH] = client_public_key.n().to_bytes_be().try_into().unwrap(); // len: 256
    let client_public_key_e_bytes: [u8; 3] = client_public_key.e().to_bytes_be().try_into().unwrap(); // len: 3
    let client_public_key_n_bytes_partial: [u8; PYLD_LENGTH-1] = client_public_key_n_bytes[..PYLD_LENGTH-1].try_into().unwrap();
    let init_pyld_partial: [u8; PYLD_LENGTH] = concat_arrays!([72], client_public_key_n_bytes_partial); // len: 25
    let init_pyld_end: [u8; 5] = concat_arrays!([71], [client_public_key_n_bytes[PYLD_LENGTH-1]], client_public_key_e_bytes); // len: 5

    println!("Loading the server public RSA key...");
    stream.write(&init_pyld_partial).expect("Failed to send payload to the server");
    stream.write(&init_pyld_end).expect("Failed to send payload to the server");

    let mut partial_server_public_key = [0 as u8; PYLD_LENGTH-OAEP_PAD-1];
    let mut data = [0; PYLD_LENGTH];
    while match stream.read(&mut data) {
        Ok(_) => {
            let data = decipher(&client_private_key, &data);
            match &data[0] {
                72 => {
                    partial_server_public_key = data[1..PYLD_LENGTH-OAEP_PAD].try_into().unwrap();
                    true
                }
                71 => {
                    let end_server_public_key: [u8; OAEP_PAD+1] = data[1..OAEP_PAD+2].try_into().unwrap();
                    let server_public_key_n_bytes :[u8; PYLD_LENGTH] = concat_arrays!(partial_server_public_key, end_server_public_key);
                    let n = BigUint::from_bytes_be(&server_public_key_n_bytes);
                    let e = BigUint::from_bytes_be(&data[OAEP_PAD+2..OAEP_PAD+5]);
                    let server_public_key = match RsaPublicKey::new(n, e) {
                        Ok(server_public_key) => {
                            println!("Secure connection successfully established !");
                            server_public_key
                        },
                        Err(_) => panic!("Failed to establish a secure connection")
                    };
                    // Account authentification
                    let mut auth = false;
                    let mut token = [0 as u8; TOKEN_LENGTH];
                    while !auth {
                        println!("Please login : (to create an account leave those inputs blank)");
                        let mut login = input("Login:");
                        let mut password = input_password("Password: ");
                        let mut conn_type = [8]; // len: 1
                        if login == "" && password == "" {
                            // Create an account
                            conn_type = [9]; // len: 1
                            println!("Create an account: (inputs are trimmed if their max length are exceeded)");
                            login = input("New login (max length: 28):");
                            password = input_password("Password (max length: 32):");
                        }
                        if login.chars().count() > NAME_LENGTH/4 {
                            login = login[0..NAME_LENGTH/4].to_string();
                        } else {
                            let pad = NAME_LENGTH/4-login.chars().count();
                            login = format!("{}{:pad$}", login, "\0").to_string();
                        }
                        if password.chars().count() > PWD_LENGTH/4 {
                            password = password[0..PWD_LENGTH/4].to_string();
                        } else {
                            let pad = PWD_LENGTH/4-password.chars().count();
                            password = format!("{}{:pad$}", password, "\0").to_string();
                        }
                        let conn_login: [u8; NAME_LENGTH] = get_u8_from_unicode(login).try_into().unwrap(); // len: 112
                        let conn_password: [u8; PWD_LENGTH] = get_u8_from_unicode(password).try_into().unwrap(); // len: 128
                        let conn_payload: [u8; 1+NAME_LENGTH+PWD_LENGTH] = concat_arrays!(conn_type, conn_login, conn_password); // len: 241
                        let encrypted_conn_payload = cipher(&server_public_key, &conn_payload); // len: 256
                        stream.write(&encrypted_conn_payload).expect("Failed to send payload to the server");
                        let mut data = [0; PYLD_LENGTH];
                        match stream.read(&mut data) {
                            Ok(_) => {
                                let data = decipher(&client_private_key, &data);
                                match &data[0] {
                                    81 => {
                                        println!("No match were found (press enter to retry)");
                                        input("");
                                    },
                                    82 => {
                                        println!("Match found ! You are now logged in");
                                        token = data[1..1+TOKEN_LENGTH].try_into().unwrap();
                                        auth = true;
                                    },
                                    91 => {
                                        println!("This name already exist please choose an other one (press enter to retry)");
                                        input("");
                                    },
                                    92 => {
                                        println!("Account successfully created, you are now logged in");
                                        token = data[1..1+TOKEN_LENGTH].try_into().unwrap();
                                        auth = true;
                                    },
                                    _ => ()
                                }
                            },
                            Err(err) => panic!("Failed to read data from the server {}", err)
                        }
                    }
                    // Authentificated
                    'main: loop {
                        let load_pyld: [u8; 1+TOKEN_LENGTH] = concat_arrays!([21], token);
                        stream.write(&cipher(&server_public_key, &load_pyld)).expect("Failed to send payload to the server");
                        let mut data = [0 as u8; PYLD_LENGTH];
                        let mut names: Vec<String> = Vec::new();
                        let mut incoming: Vec<String> = Vec::new();
                        let mut outgoing: Vec<String> = Vec::new();
                        while match stream.read(&mut data) {
                            Ok(_) => {
                                let data = decipher(&client_private_key, &data);
                                match &data[0] {
                                    211 => {
                                        extract_from(&data, &mut outgoing, &mut incoming, &mut names);
                                        println!("\n{}\n{}\n{}\n{}",
                                            "[1] Bind to",
                                            "[2] Incoming requests",
                                            "[3] Outgoing requests ",
                                            "[4] Remove Binding"
                                        );
                                        for i in 0..names.len() {
                                            println!("[{}] {}", i+5, names[i]);
                                        }
                                        println!("[q] Quit");
                                        let opt = input("Choose an option :");
                                        if opt == "q" {
                                            let req_type = [61];
                                            let req_payload: [u8; 9] = concat_arrays!(req_type, token); // len: 9
                                            stream.write(&cipher(&server_public_key, &req_payload)).expect("Failed to send payload to the server");
                                            break 'main;
                                        }
                                        match opt.parse::<i32>() {
                                            Ok(opt) => {
                                                match opt {
                                                    1 => {
                                                        let mut request_name = input("Enter name :");
                                                        if request_name.len() > NAME_LENGTH/4 {
                                                            request_name = request_name[0..NAME_LENGTH/4].to_string();
                                                        } else {
                                                            let pad = NAME_LENGTH/4-request_name.len();
                                                            request_name = format!("{}{:pad$}", request_name, "\0").to_string();
                                                        }
                                                        let req_type = [22];
                                                        let req_name: [u8; NAME_LENGTH] = get_u8_from_unicode(request_name).try_into().unwrap(); // len: 28
                                                        let req_payload: [u8; 1+TOKEN_LENGTH+NAME_LENGTH] = concat_arrays!(req_type, token, req_name); // len: 121
                                                        let encrypted_req_payload = cipher(&server_public_key, &req_payload); // len: 256
                                                        stream.write(&encrypted_req_payload).expect("Failed to send payload to the server");
                                                        let mut data = [0 as u8; PYLD_LENGTH];
                                                        while match stream.read(&mut data) {
                                                            Ok(_) => {
                                                                let data = decipher(&client_private_key, &data);
                                                                match &data[0] {
                                                                    221 => {
                                                                        println!("The request has been made (press enter to go back to the main menu)");
                                                                        input("");
                                                                        false
                                                                    },
                                                                    222 => {
                                                                        println!("This binding already exists (press enter to go back to the main menu)");
                                                                        input("");
                                                                        false
                                                                    },
                                                                    223 => {
                                                                        println!("No such name was found (press enter to go back to the main menu)");
                                                                        input("");
                                                                        false
                                                                    },
                                                                    _ => true
                                                                }
                                                            },
                                                            Err(err) => panic!("Failed to read data from the server {}", err)
                                                        } {}
                                                    },
                                                    2 => {
                                                        loop {
                                                            for i in 0..incoming.len() {
                                                                println!("[{}] {}", i+1, incoming[i]);
                                                            }
                                                            println!("[c] cancel");
                                                            let opt_incom = input("Choose an option :");
                                                            if opt_incom == "c" {
                                                                break;
                                                            } else {
                                                                match opt_incom.parse::<i32>() {
                                                                    Ok(opt_incom) => {
                                                                        let opt_incom = opt_incom - 1;
                                                                        if opt_incom < incoming.len() as i32 {
                                                                            println!("{}\n{}\n{}\n",
                                                                                "[a] Accept",
                                                                                "[d] Decline ",
                                                                                "[c] Cancel "
                                                                            );
                                                                            let opt_ad = input("Choose an option :");
                                                                            if opt_ad == "a" || opt_ad == "d" {
                                                                                let mut req_type = [22];
                                                                                if opt_ad == "d" {
                                                                                    req_type = [23];
                                                                                }
                                                                                let req_name_plain = (&incoming[opt_incom as usize]).to_string();
                                                                                let req_name: [u8; NAME_LENGTH] = get_u8_from_unicode((&req_name_plain).to_string()).try_into().unwrap(); // len: 28
                                                                                let req_payload: [u8; 1+TOKEN_LENGTH+NAME_LENGTH] = concat_arrays!(req_type, token, req_name); // len: 121
                                                                                let encrypted_req_payload = cipher(&server_public_key, &req_payload); // len: 256
                                                                                stream.write(&encrypted_req_payload).expect("Failed to send payload to the server");
                                                                                let mut data = [0 as u8; PYLD_LENGTH];
                                                                                while match stream.read(&mut data) {
                                                                                    Ok(_) => {
                                                                                        let data = decipher(&client_private_key, &data);
                                                                                        match &data[0] {
                                                                                            221 | 231 => {
                                                                                                println!("Request successfully accepted (press enter to go back to the incoming menu)");
                                                                                                incoming.retain(|name| name != &req_name_plain);
                                                                                                input("");
                                                                                                false
                                                                                            },
                                                                                            222 => {
                                                                                                println!("This binding already exists (press enter to go back to the incoming menu)");
                                                                                                input("");
                                                                                                false
                                                                                            },
                                                                                            223 | 232 => {
                                                                                                println!("No such name was found (press enter to go back to the incoming menu)");
                                                                                                input("");
                                                                                                false
                                                                                            },
                                                                                            _ => true
                                                                                        }
                                                                                    },
                                                                                    Err(err) => panic!("Failed to read data from the server {}", err)
                                                                                } {}
                                                                            }
                                                                        }
                                                                    },
                                                                    Err(_) => ()
                                                                }
                                                            }
                                                        }
                                                    },
                                                    3 | 4 => {
                                                        let mut tmp_kind = &mut outgoing;
                                                        let mut err_menu = "outgoing";
                                                        if opt == 4 {
                                                            tmp_kind = &mut names;
                                                            err_menu = "removing";
                                                        }
                                                        loop {
                                                            for i in 0..tmp_kind.len() {
                                                                println!("[{}] {}", i+1, tmp_kind[i]);
                                                            }
                                                            println!("[c] cancel");
                                                            let opt_name = input("Choose an option :");
                                                            if opt_name == "c" {
                                                                break;
                                                            } else {
                                                                match opt_name.parse::<i32>() {
                                                                    Ok(opt_name) => {
                                                                        let opt_name = opt_name - 1;
                                                                        if opt_name < tmp_kind.len() as i32 {
                                                                            println!("{}\n{}\n",
                                                                                "[r] Remove",
                                                                                "[c] Cancel "
                                                                            );
                                                                            let opt_ad = input("Choose an option :");
                                                                            if opt_ad == "r" {
                                                                                let req_type = [23];
                                                                                let req_name_plain = (&tmp_kind[opt_name as usize]).to_string();
                                                                                let req_name: [u8; NAME_LENGTH] = get_u8_from_unicode((&req_name_plain).to_string()).try_into().unwrap(); // len: 28
                                                                                let req_payload: [u8; 1+TOKEN_LENGTH+NAME_LENGTH] = concat_arrays!(req_type, token, req_name); // len: 121
                                                                                let encrypted_req_payload = cipher(&server_public_key, &req_payload); // len: 256
                                                                                stream.write(&encrypted_req_payload).expect("Failed to send payload to the server");
                                                                                let mut data = [0 as u8; PYLD_LENGTH];
                                                                                while match stream.read(&mut data) {
                                                                                    Ok(_) => {
                                                                                        let data = decipher(&client_private_key, &data);
                                                                                        match &data[0] {
                                                                                            231 => {
                                                                                                println!("Request successfully accepted (press enter to go back to the {} menu)", err_menu);
                                                                                                tmp_kind.retain(|name| name != &req_name_plain);
                                                                                                input("");
                                                                                                false
                                                                                            },
                                                                                            232 => {
                                                                                                println!("No such name was found (press enter to go back to the {} menu)", err_menu);
                                                                                                input("");
                                                                                                false
                                                                                            },
                                                                                            _ => true
                                                                                        }
                                                                                    },
                                                                                    Err(err) => panic!("Failed to read data from the server {}", err)
                                                                                } {}
                                                                            }
                                                                        }
                                                                    },
                                                                    Err(_) => ()
                                                                }
                                                            }
                                                        }
                                                    },
                                                    _ => {
                                                        if opt-5 < names.len() as i32 {
                                                            let name = String::from(&names[(opt-5) as usize]);
                                                            let mut msg_buf: Vec<u8> = Vec::new();
                                                            let retrieve_type = [5]; // len: 1
                                                            let retrieve_name: [u8; NAME_LENGTH] = get_u8_from_unicode((&name).to_string()).try_into().unwrap(); // len: 112
                                                            let nb_msg = [10]; // len: 1
                                                            let retrieve_payload: [u8; 1+TOKEN_LENGTH+NAME_LENGTH+1] = concat_arrays!(retrieve_type, token, retrieve_name, nb_msg); // len: 122
                                                            stream.write(&cipher(&server_public_key, &retrieve_payload)).expect("Failed to send payload to the server");
                                                            let mut data = [0; PYLD_LENGTH];
                                                            let mut err = false;
                                                            while match stream.read(&mut data) {
                                                                Ok(_) => {
                                                                    let data = decipher(&client_private_key, &data);
                                                                    match &data[0] {
                                                                        52 => {
                                                                            msg_buf.extend(data[1..].to_vec());
                                                                            true
                                                                        },
                                                                        53 | 51 => {
                                                                            msg_buf.extend(data[1..].to_vec());
                                                                            let mut msg_name = "";
                                                                            if msg_buf[0] == 1 {
                                                                                msg_name = &name;
                                                                            }
                                                                            let msg_content = parse_u8_to_unicode(msg_buf[1..].to_vec());
                                                                            msg_buf = Vec::new();
                                                                            println!("{}> {}", msg_name.trim(), msg_content.trim());
                                                                            println!(" <-");
                                                                            if data[0] == 51 {
                                                                                false
                                                                            } else {
                                                                                true
                                                                            }
                                                                        },
                                                                        54 => {
                                                                            println!("No such name was found (press enter to go back to the main menu)");
                                                                            input("");
                                                                            err = true;
                                                                            false
                                                                        },
                                                                        55 => {
                                                                            println!("Please make a request before sending messages (press enter to go back to the main menu)");
                                                                            input("");
                                                                            err = true;
                                                                            false
                                                                        },
                                                                        56 => {
                                                                            println!("server> This is the beginning of your messages with {}", &name);
                                                                            println!("server> To quit a chat input $quit");
                                                                            false
                                                                        },
                                                                        _ => true
                                                                    }
                                                                },
                                                                Err(err) => panic!("Failed to read data from the server {}", err)
                                                            } {}
                                                            if !err {
                                                                {
                                                                    let name = String::from(&names[(opt-5) as usize]);
                                                                    let mut stream = stream.try_clone().unwrap();
                                                                    let client_private_key = client_private_key.clone();
                                                                    thread::spawn(move || {
                                                                        let mut data = [0; PYLD_LENGTH];
                                                                        let mut msg_buf: Vec<u8> = Vec::new();
                                                                        while match stream.read(&mut data) {
                                                                            Ok(_) => {
                                                                                let data = decipher(&client_private_key, &data);
                                                                                match &data[0] {
                                                                                    11 | 12 => {
                                                                                        let msg_name = parse_u8_to_unicode(data[1..1+NAME_LENGTH].to_vec());
                                                                                        let buf: [u8; PYLD_LENGTH-OAEP_PAD-TOKEN_LENGTH-NAME_LENGTH-1] = data[1+NAME_LENGTH..PYLD_LENGTH-OAEP_PAD-TOKEN_LENGTH].try_into().unwrap();
                                                                                        if msg_name == name {
                                                                                            msg_buf.extend(buf.to_vec());
                                                                                            if data[0] == 11 {
                                                                                                let msg = parse_u8_to_unicode(msg_buf);
                                                                                                msg_buf = Vec::new();
                                                                                                let mut writer = INTERFACE.lock_writer_erase().unwrap();
                                                                                                writeln!(writer, "{}> {}", name.trim(), msg.trim()).unwrap();
                                                                                            }
                                                                                        } else {
                                                                                            let mut writer = INTERFACE.lock_writer_erase().unwrap();
                                                                                            writeln!(writer, "(You received a new message from: {})", msg_name.trim()).unwrap();
                                                                                        }
                                                                                        true
                                                                                    },
                                                                                    98 => false,
                                                                                    _ => true
                                                                                }
                                                                            },
                                                                            Err(err) => panic!("Failed to read data from the server {}", err)
                                                                        } {}
                                                                    });
                                                                }
                                                                'msg: loop {
                                                                    let res = INTERFACE.read_line().unwrap();
                                                                    match res {
                                                                        ReadResult::Input(msg) => {
                                                                            if msg == "$quit" {
                                                                                let req_type = [98];
                                                                                let req_payload: [u8; 9] = concat_arrays!(req_type, token); // len: 9
                                                                                stream.write(&cipher(&server_public_key, &req_payload)).expect("Failed to send payload to the server");
                                                                                break 'msg;
                                                                            } else if msg.trim() != "" {
                                                                                let mut buf = get_u8_from_unicode(msg);
                                                                                const LENGTH: i32 = (PYLD_LENGTH-OAEP_PAD-NAME_LENGTH-TOKEN_LENGTH-1) as i32;
                                                                                let remaining = (buf.len() % (LENGTH as usize)) as i32;
                                                                                for _ in 0..(LENGTH - remaining) {
                                                                                    buf.push(0);
                                                                                }
                                                                                let nb_of_pyld = (buf.len() / (LENGTH as usize)) as i32;
                                                                                for k in 0..nb_of_pyld {
                                                                                    let mut msg_type = [12]; // len: 1
                                                                                    if k == nb_of_pyld as i32 - 1 {
                                                                                        msg_type = [11]; // len: 1
                                                                                    }
                                                                                    let start: usize = (k*LENGTH) as usize;
                                                                                    let end: usize = ((k+1)*LENGTH) as usize;
                                                                                    let msg_part: [u8; LENGTH as usize] = buf[start..end].try_into().unwrap(); // len: 135
                                                                                    let msg_pyld: [u8; LENGTH as usize + 1+TOKEN_LENGTH+NAME_LENGTH] = concat_arrays!(msg_type, token, retrieve_name, msg_part);
                                                                                    match stream.write(&cipher(&server_public_key, &msg_pyld)) {
                                                                                        Ok(_) => {
                                                                                            if k == nb_of_pyld as i32 - 1 {
                                                                                                print!("\r <- ({} - OK)\n", k+1);
                                                                                                std::io::stdout().flush().unwrap();
                                                                                            } else {
                                                                                                print!("\r <- ({})", k+1);
                                                                                                std::io::stdout().flush().unwrap();
                                                                                            }
                                                                                        },
                                                                                        Err(err) => println!("An error occured while sending data: {}", err)
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                        _ => ()
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            },
                                            Err(_) => ()
                                        }
                                        false
                                    },
                                    212 => {
                                        extract_from(&data, &mut outgoing, &mut incoming, &mut names);
                                        true
                                    },
                                    _ => true
                                }
                            },
                            Err(err) => panic!("Failed to read data from the server {}", err)
                        } {}
                    }
                    false
                },
                _ => true
            }
        },
        Err(err) => panic!("Failed to read data from the server {}", err)
    } {};
}

fn get_u8_from_unicode(content: String) -> Vec<u8> {
    let input: Vec<char> = content.chars().collect();
    let mut u8_arr: Vec<u8> = Vec::new();
    for c in input {
        let bytes = (c as u32).to_be_bytes();
        u8_arr.extend(bytes)
    }
    u8_arr
}

fn parse_u8_to_unicode(u8_arr: Vec<u8>) -> String {
    let mut content = String::new();
    let mut i = 0;
    while i+3 < u8_arr.len() {
        let mut chr: u32 = 0;
        for j in 0..4 {
            chr += (u8_arr[i+j] as u32) << (3-j)*8;
        }
        let chr = std::char::from_u32(chr).unwrap();
        content.push(chr);
        i += 4;
    }
    content
}

fn cipher(server_public_key: &RsaPublicKey, data: &[u8]) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let padding = PaddingScheme::new_oaep::<Sha384>();
    return server_public_key.encrypt(&mut rng, padding, data).expect("failed to encrypt"); // len: 256 (PKCS + 11 bytes of default padding)
}

fn decipher(client_private_key: &RsaPrivateKey, data: &[u8; PYLD_LENGTH]) -> Vec<u8> {
    let padding = PaddingScheme::new_oaep::<Sha384>();
    return client_private_key.decrypt(padding, data).expect("failed to decrypt");
}

fn extract_from(data: &Vec<u8>, outgoing: &mut Vec<String>, incoming: &mut Vec<String>, names: &mut Vec<String>) {
    let per_pyld: i32 = ((PYLD_LENGTH-OAEP_PAD-1)/(NAME_LENGTH+1)) as i32;
    let length: i32 = (NAME_LENGTH+1) as i32;
    if data.len() > 1 {
        for i in 0..per_pyld {
            let start = 2 + (i*length) as usize;
            let end = 1 + ((i+1)*length) as usize;
            match &data[1 + (i*length) as usize] {
                1 => outgoing.push(parse_u8_to_unicode((data[start..end]).to_vec())),
                2 => incoming.push(parse_u8_to_unicode((data[start..end]).to_vec())),
                3 => names.push(parse_u8_to_unicode((data[start..end]).to_vec())),
                _ => ()
            }
        }
    }
}

fn input(target: &str) -> String {
    let mut s = String::new();
    print!("{} ", target);
    let _ = stdout().flush();
    stdin().read_line(&mut s).expect("Did not enter a correct string");
    if let Some('\n')=s.chars().next_back() {
        s.pop();
    }
    if let Some('\r')=s.chars().next_back() {
        s.pop();
    }
    return s
}

fn input_password(target: &str) -> String {
    print!("{} ", target);
    std::io::stdout().flush().unwrap();
    let password = rpassword::read_password().unwrap();
    password
}
