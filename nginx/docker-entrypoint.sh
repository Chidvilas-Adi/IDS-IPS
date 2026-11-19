#!/bin/sh
set -eu

mkdir -p /etc/nginx/ssl
if [ ! -s /etc/nginx/ssl/self-signed.crt ] || [ ! -s /etc/nginx/ssl/self-signed.key ]; then
    dns_name="${TLS_DNS_NAME:-localhost}"
    ip_address="${TLS_IP_ADDRESS:-127.0.0.1}"
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/nginx/ssl/self-signed.key \
        -out /etc/nginx/ssl/self-signed.crt \
        -subj "/CN=${dns_name}" \
        -addext "subjectAltName=DNS:${dns_name},IP:${ip_address}"
    chmod 600 /etc/nginx/ssl/self-signed.key
fi

envsubst '${TLS_PUBLIC_PORT}' \
    < /etc/nginx/nginx.conf.template \
    > /etc/nginx/nginx.conf

exec nginx -g 'daemon off;'
