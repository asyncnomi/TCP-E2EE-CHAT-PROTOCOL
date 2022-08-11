use std::thread;
use std::net::{TcpListener, TcpStream, Shutdown};
use std::io::{Read, Write, Error, ErrorKind};
use std::sync::{Arc,Mutex};
use rand::prelude::*;
use rsa::{PublicKey, RsaPrivateKey, RsaPublicKey, PaddingScheme, PublicKeyParts, BigUint};
use concat_arrays::concat_arrays;
use rusqlite::{Connection};
use sha2::{Sha256, Sha384, Digest};
use sha2::digest::generic_array::functional::FunctionalSequence;
use hex;
use lz4_flex::{compress_prepend_size, decompress_size_prepended};

const PYLD_LENGTH: usize = 512; // 512 octects
const OAEP_PAD: usize = 98; // i.e 4096 key length and sha384
const NAME_LENGTH: usize = 112; // e.g 28 unicode char
const PWD_LENGTH: usize = 128; // e.g 32 unicode char
const TOKEN_LENGTH: usize = 8; // 18x10^18

struct User {
    id: i32,
    session_id: i32,
    stream: TcpStream,
    public_key: RsaPublicKey,
}

fn main() {
    init_database();
    let online_users: Arc<Mutex<Vec<User>>> = Arc::new(Mutex::new(Vec::new()));
    let mut current_session_id: i32 = 0;
    let listener = match TcpListener::bind("127.0.0.1:2001") {
        Ok(listener) => {
            println!("Server started, waiting for connection...");
            listener
        },
        Err(err) => panic!("Cound not launch the server: {}", err)
    };
    for stream in listener.incoming() {
        current_session_id += 1;
        match stream {
            Ok(stream) => {
                println!("New connection: {}", stream.peer_addr().unwrap());
                let online_users = Arc::clone(&online_users);
                thread::spawn(move|| {
                        handle_client(stream, online_users, &current_session_id)
                });
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
}

fn handle_client(mut stream: TcpStream, online_users: Arc<Mutex<Vec<User>>>, current_session_id: &i32) {
    let mut data = [0 as u8; PYLD_LENGTH];
    let conn = load_database();
    let session_id = current_session_id.clone();
    let mut token: [u8; TOKEN_LENGTH] = rand::thread_rng().gen();
    // Generate a new RSA pair
    let mut rng = rand::thread_rng();
    let bits = PYLD_LENGTH*8;
    let server_private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let server_public_key = RsaPublicKey::from(&server_private_key);
    let mut client_public_key = server_public_key.clone();
    let mut partial_client_public_key = [0 as u8; PYLD_LENGTH-1];
    let mut secured = false;
    let mut id = -1;
    let mut id_name = String::new();
    let mut msg_buf: Vec<u8> = Vec::new();
    let mut allow_name = String::new();
    let mut allow_id = -1;

    'main: while match stream.read(&mut data) {
        Ok(_size) => {
            /*
                99 -> Unauthorized
                96 -> Clean client disconnection
                95 -> Tcp error while reading buffer (or unexpected client disconnection)
                94 -> Payload incorrectly formatted
            */
            if !secured {
                match &data[0] {
                    72 => {
                        partial_client_public_key = data[1..PYLD_LENGTH].try_into().unwrap();
                    },
                    71 => {
                        // Init connection
                        // Parse client public_key
                        let client_public_key_n_bytes: [u8; PYLD_LENGTH] = concat_arrays!(partial_client_public_key, [data[1]]);
                        let n = BigUint::from_bytes_be(&client_public_key_n_bytes);
                        let e = BigUint::from_bytes_be(&data[2..5]);
                        match RsaPublicKey::new(n, e) {
                            Ok(key) => {
                                // check rsa validity
                                let mut rng = rand::thread_rng();
                                let padding = PaddingScheme::new_oaep::<Sha384>();
                                match key.encrypt(&mut rng, padding, &token) {
                                    Ok(_) => client_public_key = key,
                                    Err(_) => {
                                        println!("Public key unvalid atp, killing connection with {}", stream.peer_addr().unwrap());
                                        kill_stream(&mut stream, &client_public_key, &online_users, session_id, 99);
                                        break 'main;
                                    }
                                }
                                // Send back the server public key
                                let server_public_key_n_bytes: [u8; PYLD_LENGTH] = server_public_key.n().to_bytes_be().try_into().unwrap(); // len: 256
                                let server_public_key_e_bytes: [u8; 3] = server_public_key.e().to_bytes_be().try_into().unwrap(); // len: 3
                                let server_public_key_n_bytes_partial: [u8; PYLD_LENGTH-OAEP_PAD-1] = server_public_key_n_bytes[..PYLD_LENGTH-OAEP_PAD-1].try_into().unwrap();
                                let server_public_key_n_bytes_end: [u8; OAEP_PAD+1] = server_public_key_n_bytes[PYLD_LENGTH-OAEP_PAD-1..].try_into().unwrap();
                                let init_pyld_partial: [u8; PYLD_LENGTH-OAEP_PAD] = concat_arrays!([72], server_public_key_n_bytes_partial); // len: 25
                                let init_pyld_end: [u8; 1+(OAEP_PAD+1)+3] = concat_arrays!([71], server_public_key_n_bytes_end, server_public_key_e_bytes); // len: 5
                                match stream.write(&cipher(&client_public_key, &init_pyld_partial)) {
                                    Ok(_) => (),
                                    Err(err) => tcp_error(err)
                                };
                                match stream.write(&cipher(&client_public_key, &init_pyld_end)) {
                                    Ok(_) => secured = true,
                                    Err(err) => tcp_error(err)
                                };
                            },
                            Err(_) => {
                                println!("Public key unvalid atp, killing connection with {}", stream.peer_addr().unwrap());
                                kill_stream(&mut stream, &client_public_key, &online_users, session_id, 99);
                                break 'main;
                            }
                        };
                    }
                    _ => ()
                }
            }
            else {
                // Decrypt data
                let data = match decipher(&server_private_key, &data) {
                    Ok(data) => data,
                    Err(_) => {
                        println!("Unauthorized atp, killing connection with {}", stream.peer_addr().unwrap());
                        kill_stream(&mut stream, &client_public_key, &online_users, session_id, 99);
                        break 'main;
                    }
                };
                // Payload are now padded by the RSA encyption, thus the length must be check
                let size = data.len();
                match data[0] {
                    8 => {
                        // Login
                        /*
                            81 -> login failed
                            82 -> Successfully logged in
                        */
                        if size != 1+NAME_LENGTH+PWD_LENGTH {
                            kill_stream(&mut stream, &client_public_key, &online_users, session_id, 94);
                            break 'main;
                        }
                        if id == -1 {
                            let login = hex::encode(&data[1..1+NAME_LENGTH]);
                            let password = &data[1+NAME_LENGTH..1+NAME_LENGTH+PWD_LENGTH];
                            let mut stmt = conn.prepare("SELECT id, login, password FROM users WHERE login = ?").unwrap();
                            let mut rows = stmt.query([&login]).unwrap();
                            let mut ids: Vec<i32> = Vec::new();
                            let mut names: Vec<String> = Vec::new();
                            let mut bdd_pwds: Vec<String> = Vec::new();
                            while let Some(row) = rows.next().unwrap() {
                                ids.push(row.get(0).unwrap());
                                names.push(row.get(1).unwrap());
                                bdd_pwds.push(row.get(2).unwrap());
                            }
                            if names.len() == 0 {
                                match stream.write(&cipher(&client_public_key, &[81])) {
                                    Ok(_) => (),
                                    Err(err) => tcp_error(err)
                                };
                            } else {
                                let name = &names[0];
                                let bdd_pwd = &bdd_pwds[0];
                                let mut hasher = Sha256::new();
                                hasher.update(password);
                                let hash = hasher.finalize().map(|s| s.to_string()).concat();
                                if &hash == bdd_pwd {
                                    let login_type = [82]; // len: 1
                                    token = rand::thread_rng().gen(); // len: 8
                                    let login_pyld: [u8; 9] = concat_arrays!(login_type, token);
                                    match stream.write(&cipher(&client_public_key, &login_pyld)) {
                                        Ok(_) => {
                                            id = ids[0];
                                            id_name = name.to_string();
                                            let mut online = online_users.lock().unwrap();
                                            online.push(User {
                                                id: id,
                                                session_id: session_id,
                                                stream: stream.try_clone().expect("cloning TcpStream failed..."),
                                                public_key: client_public_key.clone(),
                                            });
                                            println!("{} is connected", id);
                                        },
                                        Err(err) => tcp_error(err)
                                    };
                                } else {
                                    match stream.write(&cipher(&client_public_key, &[81])) {
                                        Ok(_) => (),
                                        Err(err) => tcp_error(err)
                                    };
                                }
                            }
                        }
                    },
                    9 => {
                        // Signin
                        /*
                            91 -> login name already exists
                            92 -> Account successfully created and login
                        */
                        if size != 1+NAME_LENGTH+PWD_LENGTH {
                            kill_stream(&mut stream, &client_public_key, &online_users, session_id, 94);
                            break 'main;
                        }
                        if id == -1 {
                            let login = hex::encode(&data[1..1+NAME_LENGTH]);
                            let password = &data[1+NAME_LENGTH..1+NAME_LENGTH+PWD_LENGTH];
                            let mut stmt = conn.prepare("SELECT login FROM users WHERE login = ?").unwrap();
                            let mut rows = stmt.query([&login]).unwrap();
                            let mut names: Vec<String> = Vec::new();
                            while let Some(row) = rows.next().unwrap() {
                                names.push(row.get(0).unwrap());
                            }
                            if names.len() == 0 {
                                let mut hasher = Sha256::new();
                                hasher.update(password);
                                let hash = hasher.finalize().map(|s| s.to_string()).concat();
                                let mut stmt = conn.prepare("INSERT INTO users (login, password) VALUES (?, ?)").unwrap();
                                stmt.execute((&login, hash)).unwrap();
                                let mut stmt = conn.prepare("SELECT id FROM users WHERE login = ?").unwrap();
                                let mut rows = stmt.query([&login]).unwrap();
                                let mut ids: Vec<i32> = Vec::new();
                                while let Some(row) = rows.next().unwrap() {
                                    ids.push(row.get(0).unwrap());
                                }
                                id = ids[0];
                                id_name = login.to_string();
                                let signin_type = [92]; // len: 1
                                token = rand::thread_rng().gen(); // len: 8
                                let signin_pyld: [u8; 9] = concat_arrays!(signin_type, token);
                                match stream.write(&cipher(&client_public_key, &signin_pyld)) {
                                    Ok(_) => {
                                        let mut online = online_users.lock().unwrap();
                                        online.push(User {
                                            id: id,
                                            session_id: session_id,
                                            stream: stream.try_clone().expect("cloning TcpStream failed..."),
                                            public_key: client_public_key.clone(),
                                        });
                                        println!("New user: {}", id);
                                    },
                                    Err(err) => tcp_error(err)
                                };
                            } else {
                                match stream.write(&cipher(&client_public_key, &[91])) {
                                    Ok(_) => (),
                                    Err(err) => tcp_error(err)
                                };
                            }
                        }
                    },
                    _ => {
                        // The original stream can no longer be used as a writer since it is cloned in the mutex and can be used by other threads (writing only)
                        if size < 1+TOKEN_LENGTH {
                            kill_stream(&mut stream, &client_public_key, &online_users, session_id, 94);
                            break 'main;
                        }
                        if id != -1 && token == data[1..1+TOKEN_LENGTH] {
                            match &data[0] {
                                11 | 12 => {
                                    // send msg to an id
                                    /*
                                        11 -> Last packet of a msg
                                        12 -> Partial msg
                                        13 -> Failed (not found)
                                        14 -> Failed (Not binded)
                                    */
                                    /*
                                        The binding is check for each new message but not for each part of it
                                        If two partial msg are send with differents recipient the buffer is wiped and the binding is check for the new user
                                    */
                                    // Msg must be manually padded by the client, since users input length is non constant
                                    if size != PYLD_LENGTH-OAEP_PAD {
                                        kill_stream(&mut stream, &client_public_key, &online_users, session_id, 94);
                                        break 'main;
                                    }
                                    let name = hex::encode(&data[1+TOKEN_LENGTH..1+TOKEN_LENGTH+NAME_LENGTH]);
                                    if allow_id == -1 || allow_name != name {
                                        msg_buf = Vec::new();
                                        let mut stmt = conn.prepare("SELECT id FROM users WHERE login = ?").unwrap();
                                        let mut rows = stmt.query([&name]).unwrap();
                                        let mut ids: Vec<i32> = Vec::new();
                                        while let Some(row) = rows.next().unwrap() {
                                            ids.push(row.get(0).unwrap());
                                        }
                                        if ids.len() == 1 {
                                            let mut stmt = conn.prepare("SELECT id FROM bindings WHERE (id_emitter, id_receiver) = (?, ?) OR (id_receiver, id_emitter) = (?, ?)").unwrap();
                                            let mut rows = stmt.query([&id, &ids[0], &id, &ids[0]]).unwrap();
                                            let mut ids_bind: Vec<i32> = Vec::new();
                                            while let Some(row) = rows.next().unwrap() {
                                                ids_bind.push(row.get(0).unwrap());
                                            }
                                            if ids_bind.len() == 2 {
                                                allow_name = name;
                                                allow_id = ids[0]
                                            } else {
                                                match stream_push(cipher(&client_public_key, &[14]), &online_users, session_id) {
                                                    Ok(_) => (),
                                                    Err(err) => tcp_error(err)
                                                }
                                            }
                                        } else {
                                            match stream_push(cipher(&client_public_key, &[13]), &online_users, session_id) {
                                                Ok(_) => (),
                                                Err(err) => tcp_error(err)
                                            }
                                        }
                                    }
                                    if allow_id != -1 {
                                        let buf: [u8; PYLD_LENGTH-OAEP_PAD-NAME_LENGTH-TOKEN_LENGTH-1] = data[1+TOKEN_LENGTH+NAME_LENGTH..PYLD_LENGTH-OAEP_PAD].try_into().unwrap();
                                        msg_buf.extend(buf.to_vec());
                                        let mut msg_type = [12];
                                        if data[0] == 11 {
                                            msg_type = [11];
                                        }
                                        let msg_name: [u8; NAME_LENGTH] = hex::decode(&id_name).unwrap().try_into().unwrap();
                                        let msg_pyld: [u8; PYLD_LENGTH-OAEP_PAD-TOKEN_LENGTH] = concat_arrays!(msg_type, msg_name, buf);
                                        let mut online = online_users.lock().unwrap();
                                        let mut i = 0;
                                        while i < online.len() {
                                            if online[i].id == allow_id {
                                                let key = online[i].public_key.clone();
                                                match online[i].stream.write(&cipher(&key, &msg_pyld)) {
                                                    Ok(_) => i += 1,
                                                    Err(err) => {
                                                        tcp_error(err);
                                                        let session_to_close = online[i].session_id;
                                                        online.retain(|user| user.session_id != session_to_close);
                                                        println!("Session: {} remove from online users for unreachability", session_to_close);
                                                    }
                                                };
                                            } else {
                                                i += 1;
                                            }
                                        }
                                        if data[0] == 11 {
                                            let mut stmt = conn.prepare("INSERT INTO msg (id_emitter, id_receiver, content) VALUES (?, ?, ?)").unwrap();
                                            stmt.execute((&id, &allow_id, hex::encode(compress_prepend_size(&msg_buf)))).unwrap();
                                            msg_buf = Vec::new();
                                            allow_name = String::new();
                                            allow_id = -1;
                                        }
                                    }
                                },
                                21 => {
                                    // Get list of id and pending request
                                    /*
                                        211 -> End of list
                                        212 -> Partial data
                                    */
                                    /*
                                        T:1 -> outgoing request
                                        T:2 -> incoming request
                                        T:3 -> Both
                                    */
                                    if size != 1+TOKEN_LENGTH {
                                        kill_stream(&mut stream, &client_public_key, &online_users, session_id, 94);
                                        break 'main;
                                    }
                                    let mut buf: Vec<u8> = Vec::new();
                                    let mut outgoing: Vec<String> = Vec::new();
                                    let mut incoming: Vec<String> = Vec::new();
                                    let mut stmt = conn.prepare(
                                        "SELECT users.login FROM bindings JOIN users ON bindings.id_receiver = users.id WHERE bindings.id_emitter = ?"
                                    ).unwrap();
                                    let mut rows_outgo = stmt.query([&id]).unwrap();
                                    while let Some(rows_outgo) = rows_outgo.next().unwrap() {
                                        outgoing.push(rows_outgo.get(0).unwrap());
                                    }
                                    let mut stmt = conn.prepare(
                                        "SELECT users.login FROM bindings JOIN users ON bindings.id_emitter = users.id WHERE bindings.id_receiver = ?"
                                    ).unwrap();
                                    let mut rows_incom = stmt.query([&id]).unwrap();
                                    while let Some(rows_incom) = rows_incom.next().unwrap() {
                                        incoming.push(rows_incom.get(0).unwrap());
                                    }
                                    for name in &outgoing {
                                        if incoming.contains(&name) {
                                            buf.push(3); // len: 1
                                            buf.extend(hex::decode(&name).unwrap()); // len: 1
                                        } else {
                                            buf.push(1); // len: 1
                                            buf.extend(hex::decode(&name).unwrap()); // len: 1
                                        }
                                    }
                                    for name in &incoming {
                                        if !outgoing.contains(&name) {
                                            buf.push(2); // len: 1
                                            buf.extend(hex::decode(&name).unwrap()); // len: 1
                                        }
                                    }
                                    const PER_PYLD: i32 = ((PYLD_LENGTH-OAEP_PAD-1)/(NAME_LENGTH+1)) as i32;
                                    const LENGTH: i32 = PER_PYLD*(NAME_LENGTH+1) as i32;
                                    let mut nb_of_pyld = (buf.len() as f32)/(LENGTH as f32);
                                    if nb_of_pyld - nb_of_pyld.floor() > 0.0 {
                                        nb_of_pyld += 1.0;
                                        for _z in 0..(nb_of_pyld as i32)*LENGTH-(buf.len() as i32) {
                                            buf.push(0);
                                        }
                                    }
                                    for i in 0..nb_of_pyld as i32 {
                                        let mut list_type = [212]; // len: 1
                                        if i == nb_of_pyld as i32 - 1 {
                                            list_type = [211]; // len: 1
                                        }
                                        let start: usize = (i*LENGTH) as usize;
                                        let end: usize = ((i+1)*LENGTH) as usize;
                                        let content: [u8; LENGTH as usize] = buf[start..end].try_into().unwrap();
                                        let list_pyld: [u8; LENGTH as usize + 1] = concat_arrays!(list_type, content);
                                        match stream_push(cipher(&client_public_key, &list_pyld), &online_users, session_id) {
                                            Ok(_) => (),
                                            Err(err) => tcp_error(err)
                                        }
                                    }
                                    if nb_of_pyld as i32 == 0 {
                                        match stream_push(cipher(&client_public_key, &[211]), &online_users, session_id) {
                                            Ok(_) => (),
                                            Err(err) => tcp_error(err)
                                        }
                                    }
                                },
                                22 => {
                                    // Request or accept an id
                                    /*
                                        221 -> Success
                                        222 -> Failed (already exist)
                                        223 -> Failed (not found)
                                    */
                                    if size != 1+TOKEN_LENGTH+NAME_LENGTH {
                                        kill_stream(&mut stream, &client_public_key, &online_users, session_id, 94);
                                        break 'main;
                                    }
                                    let name = hex::encode(&data[1+TOKEN_LENGTH..1+TOKEN_LENGTH+NAME_LENGTH]);
                                    let mut stmt = conn.prepare("SELECT id FROM users WHERE login = ?").unwrap();
                                    let mut rows = stmt.query([&name]).unwrap();
                                    let mut ids: Vec<i32> = Vec::new();
                                    while let Some(row) = rows.next().unwrap() {
                                        ids.push(row.get(0).unwrap());
                                    }
                                    if ids.len() == 1 {
                                        if ids[0] != id {
                                            let mut stmt = conn.prepare("SELECT id FROM bindings WHERE (id_emitter, id_receiver) = (?, ?)").unwrap();
                                            let mut rows = stmt.query([&id, &ids[0]]).unwrap();
                                            let mut ids_bind: Vec<i32> = Vec::new();
                                            while let Some(row) = rows.next().unwrap() {
                                                ids_bind.push(row.get(0).unwrap());
                                            }
                                            if ids_bind.len() == 0 {
                                                let mut stmt = conn.prepare("INSERT INTO bindings (id_emitter, id_receiver, tmp_key) VALUES (?, ?, '0')").unwrap();
                                                stmt.execute((&id, ids[0])).unwrap();
                                                match stream_push(cipher(&client_public_key, &[221]), &online_users, session_id) {
                                                    Ok(_) => (),
                                                    Err(err) => tcp_error(err)
                                                }
                                            } else {
                                                match stream_push(cipher(&client_public_key, &[222]), &online_users, session_id) {
                                                    Ok(_) => (),
                                                    Err(err) => tcp_error(err)
                                                }
                                            }
                                        } else {
                                            match stream_push(cipher(&client_public_key, &[223]), &online_users, session_id) {
                                                Ok(_) => (),
                                                Err(err) => tcp_error(err)
                                            }
                                        }
                                    } else {
                                        match stream_push(cipher(&client_public_key, &[224]), &online_users, session_id) {
                                            Ok(_) => (),
                                            Err(err) => tcp_error(err)
                                        }
                                    }
                                },
                                23 => {
                                    // Remove an id (incom and outgo i.e both)
                                    /*
                                        211 -> Success
                                        212 -> Failed (not found)
                                    */
                                    if size != 1+TOKEN_LENGTH+NAME_LENGTH {
                                        kill_stream(&mut stream, &client_public_key, &online_users, session_id, 94);
                                        break 'main;
                                    }
                                    let name = hex::encode(&data[1+TOKEN_LENGTH..1+TOKEN_LENGTH+NAME_LENGTH]);
                                    let mut stmt = conn.prepare("SELECT id FROM users WHERE login = ?").unwrap();
                                    let mut rows = stmt.query([&name]).unwrap();
                                    let mut ids: Vec<i32> = Vec::new();
                                    while let Some(row) = rows.next().unwrap() {
                                        ids.push(row.get(0).unwrap());
                                    }
                                    if ids.len() == 1 {
                                        let mut stmt = conn.prepare(
                                            "DELETE FROM bindings WHERE (id_emitter, id_receiver) = (?, ?)"
                                        ).unwrap();
                                        stmt.execute((&id, ids[0])).unwrap();

                                        let mut stmt = conn.prepare(
                                            "DELETE FROM bindings WHERE (id_emitter, id_receiver) = (? ,?)"
                                        ).unwrap();
                                        stmt.execute((ids[0], &id)).unwrap();
                                        match stream_push(cipher(&client_public_key, &[231]), &online_users, session_id) {
                                            Ok(_) => (),
                                            Err(err) => tcp_error(err)
                                        }
                                    } else {
                                        match stream_push(cipher(&client_public_key, &[232]), &online_users, session_id) {
                                            Ok(_) => (),
                                            Err(err) => tcp_error(err)
                                        }
                                    }
                                },
                                5 => {
                                    // Retrive the X last messages from a binding
                                    /*
                                        51 -> last part of a the last message
                                        52 -> Partial data
                                        53 -> last part of a message
                                        54 -> Failed (not found)
                                        55 -> Failed (not binded)
                                        56 -> Empty
                                    */
                                    /*
                                        T:0 -> emit
                                        T:1 -> receive
                                    */
                                    if size != 1+TOKEN_LENGTH+NAME_LENGTH+1 {
                                        kill_stream(&mut stream, &client_public_key, &online_users, session_id, 94);
                                        break 'main;
                                    }
                                    let name = hex::encode(&data[1+TOKEN_LENGTH..1+TOKEN_LENGTH+NAME_LENGTH]);
                                    let x = data[1+TOKEN_LENGTH+NAME_LENGTH];
                                    let mut stmt = conn.prepare("SELECT id FROM users WHERE login = ?").unwrap();
                                    let mut rows = stmt.query([&name]).unwrap();
                                    let mut ids: Vec<i32> = Vec::new();
                                    while let Some(row) = rows.next().unwrap() {
                                        ids.push(row.get(0).unwrap());
                                    }
                                    if ids.len() == 1 {
                                        let mut stmt = conn.prepare("SELECT id FROM bindings WHERE (id_emitter, id_receiver) = (?, ?) OR (id_receiver, id_emitter) = (?, ?)").unwrap();
                                        let mut rows = stmt.query([&id, &ids[0], &id, &ids[0]]).unwrap();
                                        let mut ids_bind: Vec<i32> = Vec::new();
                                        while let Some(row) = rows.next().unwrap() {
                                            ids_bind.push(row.get(0).unwrap());
                                        }
                                        if ids_bind.len() == 2 {
                                            let mut stmt = conn.prepare("SELECT * FROM (SELECT id, id_emitter, content FROM msg WHERE (id_emitter, id_receiver) = (?, ?) OR (id_receiver, id_emitter) = (?, ?) ORDER BY id DESC LIMIT ?) ORDER BY id ASC").unwrap();
                                            let mut rows = stmt.query([&id, &ids[0], &id, &ids[0], &(x as i32)]).unwrap();
                                            let mut from: Vec<u8> = Vec::new();
                                            let mut id_emitter: Vec<i32> = Vec::new();
                                            let mut content: Vec<String> = Vec::new();
                                            while let Some(row) = rows.next().unwrap() {
                                                id_emitter.push(row.get(1).unwrap());
                                                content.push(row.get(2).unwrap());
                                                if id_emitter.last().unwrap() == &id {
                                                    from.push(0);
                                                } else {
                                                    from.push(1);
                                                }
                                            }
                                            if content.len() == 0 {
                                                match stream_push(cipher(&client_public_key, &[56]), &online_users, session_id) {
                                                    Ok(_) => (),
                                                    Err(err) => tcp_error(err)
                                                }
                                            } else {
                                                for i in 0..content.len() {
                                                    const LENGTH: i32 = (PYLD_LENGTH-OAEP_PAD-1) as i32;
                                                    let msg = &content[i];
                                                    let mut buf = vec![from[i]];
                                                    buf.extend(decompress_size_prepended(&hex::decode(msg).unwrap()).unwrap());
                                                    let remaining = (buf.len() % (LENGTH as usize)) as i32;
                                                    for _ in 0..(LENGTH - remaining) {
                                                        buf.push(0);
                                                    }
                                                    let nb_of_pyld = (buf.len() / (LENGTH as usize)) as i32;
                                                    for k in 0..nb_of_pyld {
                                                        let mut msg_type = [52]; // len: 1
                                                        if k == nb_of_pyld as i32 - 1 {
                                                            if i == (content.len() as i32 - 1) as usize {
                                                                msg_type = [51];
                                                            } else {
                                                                msg_type = [53]; // len: 1
                                                            }
                                                        }
                                                        let start: usize = (k*LENGTH) as usize;
                                                        let end: usize = ((k+1)*LENGTH) as usize;
                                                        let msg_part: [u8; LENGTH as usize] = buf[start..end].try_into().unwrap(); // len: 255
                                                        let msg_pyld: [u8; LENGTH as usize + 1] = concat_arrays!(msg_type, msg_part);
                                                        match stream_push(cipher(&client_public_key, &msg_pyld), &online_users, session_id) {
                                                            Ok(_) => (),
                                                            Err(err) => tcp_error(err)
                                                        }
                                                    }
                                                }
                                            }
                                        } else {
                                            match stream_push(cipher(&client_public_key, &[55]), &online_users, session_id) {
                                                Ok(_) => (),
                                                Err(err) => tcp_error(err)
                                            }
                                        }
                                    } else {
                                        match stream_push(cipher(&client_public_key, &[54]), &online_users, session_id) {
                                            Ok(_) => (),
                                            Err(err) => tcp_error(err)
                                        }
                                    }
                                },
                                61 => {
                                    // Close the connection (disconnect)
                                    /*
                                        96 -> Stream close
                                    */
                                    if size != 1+TOKEN_LENGTH {
                                        kill_stream(&mut stream, &client_public_key, &online_users, session_id, 94);
                                        break 'main;
                                    }
                                    println!("Terminating connection with {}", stream.peer_addr().unwrap());
                                    kill_stream(&mut stream, &client_public_key, &online_users, session_id, 96);
                                    break 'main;
                                }
                                97 => {
                                    // Delete account
                                },
                                98 => {
                                    // Ping-Pong or event fire
                                    if size != 1+TOKEN_LENGTH {
                                        kill_stream(&mut stream, &client_public_key, &online_users, session_id, 94);
                                        break 'main;
                                    }
                                    match stream_push(cipher(&client_public_key, &[98]), &online_users, session_id) {
                                        Ok(_) => (),
                                        Err(err) => tcp_error(err)
                                    }
                                }
                                _ => ()
                            }
                        } else {
                            println!("Unauthorized atp, killing connection with {}", stream.peer_addr().unwrap());
                            kill_stream(&mut stream, &client_public_key, &online_users, session_id, 99);
                            break 'main;
                        }
                    }
                }
            }
            true
        },
        Err(_) => {
            println!("Terminating connection with {}", stream.peer_addr().unwrap());
            kill_stream(&mut stream, &client_public_key, &online_users, session_id, 95);
            false
        }
    } {}
}

fn init_database() {
    match Connection::open("msg_encrypt.db") {
        Ok(conn) => {
            conn.execute(
                "create table if not exists users (
                    id integer primary key,
                    login text not null unique,
                    password text not null
                )",
                [],
            ).unwrap();
            conn.execute(
                "create table if not exists bindings (
                    id integer primary key,
                    id_emitter integer not null,
                    id_receiver integer not null,
                    tmp_key text not null
                )",
                [],
            ).unwrap();
            conn.execute(
                "create table if not exists msg (
                    id integer primary key,
                    id_emitter integer not null,
                    id_receiver integer not null,
                    content text not null
                )",
                [],
            ).unwrap();
        },
        Err(err) => panic!("Cound not load or create the database: {}", err)
    };
}

fn load_database() -> Connection {
    match Connection::open("msg_encrypt.db") {
        Ok(conn) => conn,
        Err(err) => panic!("Cound not load or create the database: {}", err)
    }
}

fn cipher(client_public_key: &RsaPublicKey, data: &[u8]) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let padding = PaddingScheme::new_oaep::<Sha384>();
    return client_public_key.encrypt(&mut rng, padding, data).expect("failed to encrypt");
}

fn decipher(server_private_key: &RsaPrivateKey, data: &[u8]) -> Result<Vec<u8>, rsa::errors::Error> {
    let padding = PaddingScheme::new_oaep::<Sha384>();
    return server_private_key.decrypt(padding, data);
}

fn stream_push(data: Vec<u8>, online_users: &Arc<Mutex<Vec<User>>>, session_id: i32) -> Result<usize, std::io::Error> {
    let mut online = online_users.lock().unwrap();
    for i in 0..online.len() {
        if online[i].session_id == session_id {
            return online[i].stream.write(&data);
        }
    }
    return Err(Error::new(ErrorKind::Other, "Socket not found"));
}

fn kill_stream(stream: &mut TcpStream, client_public_key: &RsaPublicKey, online_users: &Arc<Mutex<Vec<User>>>, session_id: i32, response_type: u8) {
    match stream.write(&cipher(client_public_key, &[response_type])) {
        Ok(_) => (),
        Err(err) => tcp_error(err)
    };
    let mut online = online_users.lock().unwrap();
    online.retain(|user| user.session_id != session_id);
    stream.shutdown(Shutdown::Both).unwrap();
    println!("Stream killed for user: {}", stream.peer_addr().unwrap());
}

fn tcp_error(err: std::io::Error) {
    println!("An error occured while sending data: {}", err);
}
