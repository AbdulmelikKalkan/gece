# gece

GeCe is a simple generate certificate system. Gece can generate certificate authority,certificate and sign certificate with CA.
it will help us for our ssl needs in our local environments.

## Usage
```bash
go build

## Generate certificate authority
./gece -ca -outpem ca.pem -outkey ca.key

## Generate certificate
./gece -cert -outpem cert.pem -outkey cert.key

## Generate certificate and sign ca
./gece -cert -sign-ca -outpem cert.pem -outkey cert.key

## Generate certificate and sign with ca which is given from arguments
./gece -cert -sign-ca -inca ca.pem -inkey ca.key -outpem cert.pem -outkey cert.key
```