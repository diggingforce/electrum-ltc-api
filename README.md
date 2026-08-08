# electrum-ltc-api

A tiny REST API for [Electrum-LTC](https://electrum-ltc.org/) which lets you create wallets, check balances, send Litecoin. Written in Rust :).

## Quick start

Make sure you have:
- Rust 1.85+
- [Electrum-LTC](https://electrum-ltc.org/) (the `daemon` command is required)

commands to run:
```bash
cargo build --release
cp .env.example .env # rename to .env
cargo run --release #run it
```

Server listens on `0.0.0.0:8080`. 

## How the API works

The API talks to the electrum daemon via its Unix socket at `~/.electrum-ltc/daemon_rpc_socket`. Make sure its up and running

```bash
electrum-ltc daemon -d
```

If it needs user and pass, put them in `~/.electrum-ltc/config` and restart the daemon

```json
{
  "rpcuser": "user",
  "rpcpassword": "your-password"
}
```

Copy `config.example.toml` to `config.toml` if you want to change anything.

## Endpoints

Everything needs the `x-api-key` header.

- `POST /wallet/create/:name` — make a new wallet, returns address and WIF key
- `GET /wallet/balance/:name`
- `GET /wallet/address/:name`
- `GET /wallet/transactions/:name` — checks incoming txs only
- `POST /wallet/send/:name` — takes JSON `{"to": "ltc_address", "amount": "0.1"}`
- `POST /wallet/restore/:any` — takes JSON `{"name": "name", "wif": "wif_key"}`
- `POST /wallet/delete/:name`
- `POST /wallet/reload` — reloads the daemon and all wallets (it can be a lil heavy)

## Example

```bash
curl -k -X POST https://localhost:8080/wallet/create/test \
  -H "x-api-key: your-key"
```

And that's all!

## License

MIT
