# Setup

## What you need
- Rust 1.70+
- Electrum-LTC
- OpenSSL

## Steps

1. **Install Electrum-LTC**
   ```bash
   sudo apt-get install electrum-ltc
   ```

2. **Set API Key**
   ```bash
   cp .env.example .env
   # edit .env and change API_KEY
   ```

3. **Generate certs**
   ```bash
   ./generate-certs.sh
   ```

4. **Build & Run**
   ```bash
   cargo build --release
   cargo run --release
   ```

5. **Test**
   ```bash
   curl -k -X POST https://localhost:8080/wallet/create/test \
     -H "x-api-key: your-key"
   ```

## Structure

```
electrum-ltc-api/
├── src/              # source
├── certs/            # auto-generated, gitignored
├── Cargo.toml        # dependencies
├── .env.example      # template
├── generate-certs.sh # cert script
└── README.md         # docs
```

## Notes

- `certs/` gets created by the script
- Never commit `.env` or `certs/`
- Use real CA certs for production
