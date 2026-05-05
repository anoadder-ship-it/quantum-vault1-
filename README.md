# KwantumKluis — Quantum Veilige Air-Gapped Wallet

**Ultra-secure, quantum-resistant cryptocurrency cold wallet** geschreven in Rust.

### Kenmerken
- BIP39 24-woorden seed + SHAKE256 derivation
- Hybrid signatures (Ed25519 + Forward-secure WOTS-laag)
- Air-gap ready (Base64 → QR-code transport)
- Ondersteuning voor Solana, Ethereum, Bitcoin (uitbreidbaar)
- Zeroize memory protection
- Geen internet verbinding nodig tijdens signing (true cold storage)

### Installatie & Gebruik

```bash
git clone https://github.com/anoadder-ship-it/kwantumkluis1-.git
cd kwantumkluis1-
cargo run --release
