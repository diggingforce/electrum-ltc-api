# electrum-ltc-api

REST API wrapper around Electrum-LTC for managing Litecoin wallets. Written in Rust.

## What it does

- Create and restore Litecoin wallets
- Send transactions with automatic fee calculation
- Check balances and transaction history
- HTTPS with API key auth
- Async runtime (Tokio + Axum)

## Setup

You'll need:
- Rust 1.70+
- [Electrum-LTC](https://electrum-ltc.org/) 
- OpenSSL

```bash
git clone https://github.com/diggingforce/electrum-ltc-api.git
cd electrum-ltc-api

# Install Electrum-LTC if you don't have it
sudo apt-get install electrum-ltc

# Generate self-signed certs for HTTPS
./generate-certs.sh

# Set your API key
echo "API_KEY=something-secret" > .env

# Build and run
cargo build --release
cargo run --release
```

Server runs on `https://0.0.0.0:8080` by default.

If you're using curl, add `-k` to skip cert verification (self-signed certs trigger warnings).

## API

All requests need `x-api-key` header.

**Create wallet**
```bash
POST /wallet/create/:name
```
Returns address and WIF private key.

**Get balance**
```bash
GET /wallet/balance/:name
```

**Get address**
```bash
GET /wallet/address/:name
```

**Transaction history**
```bash
GET /wallet/transactions/:name
```
Shows incoming txs only.

**Send LTC**
```bash
POST /wallet/send/:name
Content-Type: application/json

{"to": "LTC_ADDRESS", "amount": "0.1"}
```
Fee is auto-calculated and deducted from amount.

**Restore wallet**
```bash
POST /wallet/restore/:any
Content-Type: application/json

{"name": "wallet-name", "wif": "YOUR_WIF_KEY"}
```

**Delete wallet**
```bash
POST /wallet/delete/:name
```

**Reload daemon**
```bash
POST /wallet/reload
```
Restarts Electrum daemon and reloads all wallets.

## Examples

```bash
# Create wallet
curl -k -X POST https://localhost:8080/wallet/create/test \
  -H "x-api-key: your-key"

# Check balance
curl -k https://localhost:8080/wallet/balance/test \
  -H "x-api-key: your-key"

# Send 0.1 LTC
curl -k -X POST https://localhost:8080/wallet/send/test \
  -H "x-api-key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"to":"LTC_ADDRESS","amount":"0.1"}'
```

## Security

**Important:**
- Use a strong random API key
- Don't commit `.env` to git
- Get proper certificates for production (not self-signed)
- WIF keys = access to funds. Keep them safe.
- Put nginx or caddy in front for production
- Test with small amounts first

## Configuration

Edit `config.toml` to customize paths and settings:

```toml
[server]
host = "0.0.0.0"
port = 8080

[paths]
cert = "certs/cert.crt"
key = "certs/cert.key"
# wallet_dir = "/custom/path"  # optional, defaults to ~/.electrum-ltc/wallets

[electrum]
command = "electrum-ltc"
```

Set `CONFIG_PATH` env var to use a different config file.

## Development

```bash
cargo run        # dev mode
cargo test       # tests
cargo check      # check without building
cargo fmt        # format code
```

## License

MIT

## Contributing

PRs welcome.

## Disclaimer

No warranty. Use at your own risk. Test with small amounts.
