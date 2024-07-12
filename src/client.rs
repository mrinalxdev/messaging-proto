use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use ed25519_dalek::{Keypair, Signer, PublicKey};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

struct Client {
    id: String,
    keypair: Keypair,
    server_pubkey: Option<PublicKey>,
}

impl Client {
    fn new(id: &str) -> Self {
        let keypair = Keypair::generate(&mut OsRng);
        Client {
            id: id.to_string(),
            keypair,
            server_pubkey: None,
        }
    }

    async fn register(&mut self, addr: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut stream = TcpStream::connect(addr).await?;
        let msg = format!("REGISTER:{}:{}", self.id, hex::encode(self.keypair.public.as_bytes()));
        stream.write_all(msg.as_bytes()).await?;

        let mut buf = [0; 1024];
        let n = stream.read(&mut buf).await?;
        let response = String::from_utf8_lossy(&buf[..n]);
        let parts: Vec<&str> = response.split(':').collect();
        if parts[0] == "REGISTERED" {
            self.server_pubkey = Some(PublicKey::from_bytes(&hex::decode(parts[1])?)?);
            println!("Registered successfully");
        }
        Ok(())
    }

    async fn send_message(&self, addr: &str, recipient: &str, msg: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut stream = TcpStream::connect(addr).await?;
        let secret = StaticSecret::new(OsRng);
        let public = X25519PublicKey::from(&secret);
        
        let encrypted_msg = format!("{}:{}", hex::encode(public.as_bytes()), msg);
        let signature = self.keypair.sign(encrypted_msg.as_bytes());
        
        let send_msg = format!("SEND:{}:{}:{}:{}",
            self.id,
            recipient,
            hex::encode(encrypted_msg.as_bytes()),  // Encode the entire encrypted message
            hex::encode(signature.to_bytes())
        );
        println!("Sending message: {}", send_msg);
        stream.write_all(send_msg.as_bytes()).await?;
        println!("Message sent");
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = Client::new("Mrinal");
    client.register("127.0.0.1:8080").await?;
    client.send_message("127.0.0.1:8080", "Elon", "Hello Elon").await?;
    Ok(())
}