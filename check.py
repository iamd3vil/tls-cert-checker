#!/usr/bin/env python3

import ssl
import socket
import datetime
import sys

# Check if hostname and port are provided as command line arguments
if len(sys.argv) != 3:
    print("Usage: python check.py <hostname> <port>")
    sys.exit(1)

# Get hostname and port from command line arguments
hostname = sys.argv[1]
port = int(sys.argv[2])

# Create an SSL context
context = ssl.create_default_context()


def tuple_to_dict(t):
    d = {}
    for item in t:
        key = item[0][0]
        value = item[0][1]
        d[key] = value
    return d


# Create a socket to connect to the server
with socket.create_connection((hostname, port)) as sock:
    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
        # Get the server's certificate
        cert = ssock.getpeercert()

        # Extract the expiration date from the certificate
        exp_date = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")

        # Get the certificate issuer
        issuer_list = tuple_to_dict(cert["issuer"])
        org_name = issuer_list["organizationName"]
        country_name = issuer_list["countryName"]
        common_name = issuer_list["commonName"]

        # Get the current date and time
        now = datetime.datetime.now()

        # Calculate the number of days until the certificate expires
        days_until_expiry = (exp_date - now).days

        # Get the TLS version and ciphers used
        tls_version = ssock.version()
        ciphers = ssock.cipher()

        # Print the certificate's expiration date, days until expiry, TLS version, ciphers used, and issuer
        print("Certificate expires on:", exp_date)
        print("Days until certificate expiry:", days_until_expiry)
        print("TLS version:", tls_version)
        print("Ciphers used:", ciphers)
        print(f"Issuer: {org_name}, {common_name}, {country_name}")
