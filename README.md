# TLS Cert Checker

A simple python script to check certificate attributes of a TLS server.

Shows expiry, issuer, tls version and cipher used to connect.

## Usage

```bash
$ ./check.py google.com 443
Certificate expires on: 2023-06-05 08:18:00
Days until certificate expiry: 60
TLS version: TLSv1.3
Ciphers used: ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)
Issuer: Google Trust Services LLC, GTS CA 1C3, US
```
