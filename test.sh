#!/bin/bash
set -euxo pipefail

certdir=$(mktemp -d)

cleanup() {
    status=$?
    rm -f private-ca*
    rm -rf "${certdir}"
    killall private-ca-server || true
    caddy stop || true
    exit "${status}"
}
trap 'cleanup' EXIT

go build -o . ./...

# Create a root cert...
./private-ca-init --out "${certdir}" \
                  --domain "localhost"

# Create a client cert for localhost...
./private-ca --signer "${certdir}/localhost.ca.pem" \
             --host "localhost" \
             --out "${certdir}"

# Start a CA...
./private-ca-server --signer "${certdir}/localhost.ca.pem" \
                    --host "localhost" \
                    --client-roots "${certdir}/root.pem"&
sleep 1

# Renew our cert, printing a before and after
echo 'Before renewal...'
certigo dump -v "${certdir}/localhost.pem"
cat "${certdir}/localhost.pem"
./private-ca-client --pem "${certdir}/localhost.pem" \
                    --ca "${certdir}/root.pem" \
                    --url "https://localhost:8080"
echo 'After renewal...'
certigo dump -v "${certdir}/localhost.pem"
cat "${certdir}/localhost.pem"

# Start an HTTPS server...
cat <<EOF > "${certdir}/Caddyfile"
localhost:8443 {
          tls ${certdir}/localhost.pem ${certdir}/localhost.pem
          respond "Hello, world!"
}
EOF
caddy fmt "${certdir}/Caddyfile"
caddy stop || true
caddy start --config "${certdir}/Caddyfile"

# And connect to it...
certigo connect localhost:8443 \
        -v \
        --verify \
        --ca "${certdir}/root.pem" \
        --expected-name localhost


