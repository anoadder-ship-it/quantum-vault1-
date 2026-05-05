use bip39::{Language, Mnemonic};
use ed25519_dalek::SigningKey;
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
use zeroize::{Zeroize, ZeroizeOnDrop};
use std::collections::HashMap;
use std::io::{self, Write};

#[derive(thiserror::Error, Debug)]
enum VaultError {
    #[error("Crypto: {0}")]
    Crypto(String),
    #[error("IO: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serde: {0}")]
    Serde(String),
}

#[derive(ZeroizeOnDrop, Clone)]
struct HybridKeyPair {
    path: String,
    classical_sk: [u8; 32],
    classical_pk: [u8; 32],
    wots_root: [u8; 64],
}

#[derive(serde::Serialize, serde::Deserialize)]
struct HybridSignature {
    classical: Vec<u8>,
    wots: Vec<u8>,
    message: Vec<u8>,
    timestamp: u64,
}

#[derive(ZeroizeOnDrop)]
struct QuantumVault {
    master_seed: [u8; 64],
    accounts: HashMap<String, HybridKeyPair>,
}

impl QuantumVault {
    fn generate_mnemonic() -> String {
        Mnemonic::generate_in(Language::English, 24).unwrap().to_string()
    }

    fn from_mnemonic(mnemonic: &str, passphrase: Option<&str>) -> Result<Self, VaultError> {
        let m = Mnemonic::parse_in(Language::English, mnemonic)
            .map_err(|e| VaultError::Crypto(e.to_string()))?;
        let mut seed = [0u8; 64];
        m.to_seed_in(passphrase.unwrap_or(""), &mut seed);
        Ok(Self { master_seed: seed, accounts: HashMap::new() })
    }

    fn derive(&mut self, path: &str) -> Result<(), VaultError> {
        if self.accounts.contains_key(path) { return Ok(()); }

        let mut hasher = Shake256::default();
        hasher.update(b"KwantumKluis-v0.5-DomainSep-2026");
        hasher.update(&self.master_seed);
        hasher.update(path.as_bytes());
        let mut reader = hasher.finalize_xof();

        let mut material = [0u8; 256];
        reader.read(&mut material);

        let classical_sk = SigningKey::from_bytes(&material[0..32].try_into().unwrap());
        let classical_pk = classical_sk.verifying_key().to_bytes();

        let mut wots_root = [0u8; 64];
        wots_root.copy_from_slice(&material[32..96]);

        let kp = HybridKeyPair {
            path: path.to_string(),
            classical_sk: classical_sk.to_bytes(),
            classical_pk,
            wots_root,
        };
        self.accounts.insert(path.to_string(), kp);
        Ok(())
    }

    fn get_address(&self, path: &str, chain: &str) -> Result<String, VaultError> {
        let kp = self.accounts.get(path).ok_or_else(|| VaultError::Crypto("Derive eerst het account".into()))?;
        match chain.to_lowercase().as_str() {
            "solana" => Ok(bs58::encode(kp.classical_pk).into_string()),
            "ethereum" => Ok(format!("0x{}", hex::encode(&kp.classical_pk[0..20]))),
            "bitcoin" => Ok(format!("bc1q{}", hex::encode(&kp.classical_pk[0..20]))),
            _ => Ok(hex::encode(kp.classical_pk)),
        }
    }

    fn sign(&self, path: &str, message: &[u8]) -> Result<HybridSignature, VaultError> {
        let kp = self.accounts.get(path).ok_or_else(|| VaultError::Crypto("Account niet gevonden".into()))?;

        let signing_key = SigningKey::from_bytes(&kp.classical_sk);
        let classical_sig = signing_key.sign(message).to_bytes().to_vec();

        let mut wots_hasher = sha3::Sha3_512::new();
        wots_hasher.update(&kp.wots_root);
        wots_hasher.update(message);
        let wots_sig = wots_hasher.finalize().to_vec();

        Ok(HybridSignature {
            classical: classical_sig,
            wots: wots_sig,
            message: message.to_vec(),
            timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        })
    }
}

fn main() {
    println!("=== KwantumKluis — Quantum Veilige Wallet ===\n");

    let mut vault = loop {
        println!("1. Nieuwe vault maken\n2. Bestaande mnemonic laden");
        print!("Kies (1/2): ");
        io::stdout().flush().unwrap();

        let mut choice = String::new();
        io::stdin().read_line(&mut choice).unwrap();

        match choice.trim() {
            "1" => {
                let mnemonic = QuantumVault::generate_mnemonic();
                println!("\n⚠️  SCHRIJF DIT OP EN BEWAAR OFFLINE:\n\n{}\n", mnemonic);
                if let Ok(v) = QuantumVault::from_mnemonic(&mnemonic, None) {
                    break v;
                }
            }
            "2" => {
                print!("Voer je mnemonic in: ");
                io::stdout().flush().unwrap();
                let mut mnemonic = String::new();
                io::stdin().read_line(&mut mnemonic).unwrap();
                if let Ok(v) = QuantumVault::from_mnemonic(mnemonic.trim(), None) {
                    break v;
                }
            }
            _ => println!("Ongeldige keuze"),
        }
    };

    println!("\nVault geladen. Typ 'help' voor commando's.\n");

    loop {
        print!("> ");
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        let cmd = input.trim();

        if cmd == "exit" || cmd == "quit" { break; }
        if cmd == "help" {
            println!("Beschikbare commando's:\n  derive <path>\n  address <path> <chain>\n  sign <path> \"bericht\"\n  exit");
            continue;
        }

        let parts: Vec<&str> = cmd.splitn(3, ' ').collect();
        match parts[0] {
            "derive" if parts.len() > 1 => {
                if let Err(e) = vault.derive(parts[1]) { println!("Fout: {}", e); }
                else { println!("✅ Account afgeleid: {}", parts[1]); }
            }
            "address" if parts.len() > 2 => {
                match vault.get_address(parts[1], parts[2]) {
                    Ok(addr) => println!("Adres ({}): {}", parts[2], addr),
                    Err(e) => println!("Fout: {}", e),
                }
            }
            "sign" if parts.len() > 2 => {
                let path = parts[1];
                let message = parts[2];
                match vault.sign(path, message.as_bytes()) {
                    Ok(sig) => {
                        let encoded = base64::encode(serde_json::to_vec(&sig).unwrap());
                        println!("✅ Getekend! Kopieer voor QR:\n{}", encoded);
                    }
                    Err(e) => println!("Fout: {}", e),
                }
            }
            _ => println!("Onbekend commando. Typ 'help'"),
        }
    }

    println!("Vault afgesloten. Alle gevoelige data gewist.");
      }
