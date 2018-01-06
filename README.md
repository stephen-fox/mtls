# mtls - TLS Mutual Authentication

## What is it?
A Go library and application capable of generating certificate and private
key pairs which can be used for TLS mutual authentication.

Per [Wikipedia](https://en.wikipedia.org/wiki/Mutual_authentication):
```
Mutual authentication or two-way authentication refers to two parties
authenticating each other at the same time, being a default mode of
authentication in some protocols (IKE, SSH) and optional in others (TLS).
```

In other words, the server will reject the client if the client does not
provide the correct certificate and key, and the client will reject the
server if the server does not provide the correct certificate and key.

This authentication method is particularly useful for services running on an
end user's machine, or for services with only one consumer. This package
provides automation for generating the certificate and private key.

## How do I use the application?
By default, the application creates a `certificate.crt` and a
`private-key.pem` in the current working directory. These two files are
needed to facilitate TLS mutual authentication by **both** the client and
the server.

There are several use cases which may change how you use the application.

If you would like to generate a mTLS pair for an IP address, do the following:
```bash
$ mtls -o "Junk, Inc." -i 127.0.0.1
```

If you would like to generate a mTLS pair that supports several organizations,
separate them by pipes `|`:
```bash
$ mtls -o 'Junk, Inc.|Better Junk LLC.' -i 127.0.0.1
```

If you would like to generate a mTLS pair that supports several IP addresses,
separate them by commas `,`:
```bash
$ mtls -o "Junk, Inc." -i 192.168.1.10,192.168.2.5
```

If you would like to generate a mTLS pair for a DNS address:
```bash
$ mtls -o "Junk, Inc." -d mycoolsite.com
```

If you would like to generate a mTLS pair that supports several DNS addresses,
separate them by commas `,`:
```bash
$ mtls -o "Junk, Inc." -d mycoolsite.com,anothersite.net
```

You can view additional examples by running the application with `-x`:
```bash
$ mtls -x
```

## TLS mutual authentication in practice
The following steps describe how to run a web server that uses mTLS.

1. Run the included example server:
```bash
$ go run cmd/mtls-server-example/main.go
```

2. In a separate terminal, execute `curl`:
```bash
$ curl \
    --cacert certificate.crt \
    --cert certificate.crt \
    --key private-key.pem \
    -X 'GET' \
    https://127.0.0.1:8888/test
```
