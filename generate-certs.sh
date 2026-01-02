#!/bin/bash

# Generate self-signed certs for dev/testing

set -e

CERT_DIR="certs"

echo "Creating certs directory..."
mkdir -p "$CERT_DIR"

echo "Generating certificate..."
openssl req -x509 -newkey rsa:4096 \
    -keyout "$CERT_DIR/cert.key" \
    -out "$CERT_DIR/cert.crt" \
    -days 365 -nodes \
    -subj "/C=US/ST=State/L=City/O=Org/CN=localhost"

echo "Done!"
echo "  - $CERT_DIR/cert.crt"
echo "  - $CERT_DIR/cert.key"
echo ""
echo "Note: Self-signed only. Use real certs for production."
