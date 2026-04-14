#!/usr/bin/env bash
set -euo pipefail

mkdir -p certs
cd certs

cat > ca_ext.cnf <<'EOF'
basicConstraints=critical,CA:true
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
EOF

cat > server_ext.cnf <<'EOF'
basicConstraints=critical,CA:false
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

cat > client_ext.cnf <<'EOF'
basicConstraints=critical,CA:false
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

# CA cert (v3 CA)
openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
  -keyout ca.key -out ca.crt \
  -subj "/CN=ZK-Compare Test CA" \
  -extensions v3_ca \
  -config <(cat /etc/ssl/openssl.cnf <(printf "\n[v3_ca]\n") ca_ext.cnf)

# Server key + CSR
openssl req -newkey rsa:2048 -sha256 -nodes \
  -keyout server.key -out server.csr \
  -subj "/CN=localhost"

# Sign server cert as v3 end-entity
openssl x509 -req -sha256 -in server.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 365 \
  -extfile server_ext.cnf

# Client key + CSR
openssl req -newkey rsa:2048 -sha256 -nodes \
  -keyout client.key -out client.csr \
  -subj "/CN=zk-compare-client"

# Sign client cert as v3 end-entity
openssl x509 -req -sha256 -in client.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days 365 \
  -extfile client_ext.cnf

echo "Certificates written to ./certs"
openssl x509 -in server.crt -noout -text | grep "Version:"
openssl x509 -in client.crt -noout -text | grep "Version:"