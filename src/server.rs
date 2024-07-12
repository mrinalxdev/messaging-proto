use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier};
use hex::FromHexError;
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

struct Server {
    keypair: Keypair,
    clients: Arc<Mutex<HashMap<String, PublicKey>>>,
}

impl Server {
    fn new() -> Self {
        let keypair = Keypair::generate(&mut OsRng);
        Server {
            keypair,
            clients: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn run(&self, addr: &str) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(addr).await?;
        println!("Server listening on {}", addr);

        loop {
            let (mut socket, _) = listener.accept().await?;
            let clients = Arc::clone(&self.clients);
            let server_pubkey = self.keypair.public;

            tokio::spawn(async move {
                let mut buf = [0; 1024];
                let n = socket.read(&mut buf).await.unwrap();
                let msg = String::from_utf8_lossy(&buf[..n]);
                let parts: Vec<&str> = msg.split(':').collect();

                if parts[0] == "REGISTER" {
                    if parts.len() != 3 {
                        println!("Invalid REGISTER format");
                        return;
                    }
                    let client_id = parts[1].to_string();
                    let client_pubkey = match PublicKey::from_bytes(&hex::decode(parts[2]).unwrap())
                    {
                        Ok(key) => key,
                        Err(e) => {
                            println!("Failed to parse client public key: {:?}", e);
                            return;
                        }
                    };
                    clients
                        .lock()
                        .await
                        .insert(client_id.clone(), client_pubkey);
                    let response = format!("REGISTERED:{}", hex::encode(server_pubkey.as_bytes()));
                    socket.write_all(response.as_bytes()).await.unwrap();
                    println!("Client registered: {}", client_id);
                } else if parts[0] == "SEND" {
                    println!("Received SEND command: {}", msg);
                    println!("Received SEND command: {}", msg);
                    if parts.len() != 5 {
                        println!("Invalid SEND format. Expected 5 parts, got {}", parts.len());
                        return;
                    }
                    let sender_id = parts[1];
                    let recipient_id = parts[2];
                    let encrypted_msg = match hex::decode(parts[3]) {
                        Ok(decoded) => String::from_utf8_lossy(&decoded).to_string(),
                        Err(e) => {
                            println!("Failed to decode encrypted message: {:?}", e);
                            return;
                        }
                    };
                    let signature_hex = parts[4];

                    println!("Received signature hex: {}", signature_hex);

                    let signature_bytes = match hex::decode(signature_hex) {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            println!("Failed to decode signature: {:?}", e);
                            return;
                        }
                    };

                    let signature = match Signature::from_bytes(&signature_bytes) {
                        Ok(sig) => sig,
                        Err(e) => {
                            println!("Failed to create signature from bytes: {:?}", e);
                            return;
                        }
                    };

                    let clients = clients.lock().await;
                    let sender_pubkey = match clients.get(sender_id) {
                        Some(key) => key,
                        None => {
                            println!("Unknown sender: {}", sender_id);
                            return;
                        }
                    };

                    if let Err(e) = sender_pubkey.verify(encrypted_msg.as_bytes(), &signature) {
                        println!("Signature verification failed: {:?}", e);
                        return;
                    }

                    let recipient_pubkey = match clients.get(recipient_id) {
                        Some(key) => key,
                        None => {
                            println!("Unknown recipient: {}", recipient_id);
                            return;
                        }
                    };

                    let forward_msg = format!(
                        "MSG:{}:{}:{}",
                        sender_id,
                        encrypted_msg,
                        hex::encode(signature.to_bytes())
                    );
                    println!("Forwarding to {}: {}", recipient_id, forward_msg);
                } else {
                    println!("Unknown command: {}", parts[0]);
                }
            });
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Let's get started with secured message protocol");
    println!("Server starting soon !!");
    let server = Server::new();
    server.run("127.0.0.1:8080").await
}
