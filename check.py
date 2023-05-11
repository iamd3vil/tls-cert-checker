#!/usr/bin/env python3

import argparse
import datetime
import socket
import ssl
import sys


def tuple_to_dict(t):
    d = {}
    for item in t:
        key = item[0][0]
        value = item[0][1]
        d[key] = value
    return d


def print_ssl_info(
    hostname: str,
    port: int,
    print_all: bool,
    print_cert_expiry: bool,
    print_issue_date: bool,
    print_days_to_expiry: bool,
    print_tls_version: bool,
    print_ciphers_used: bool,
    print_issuer_info: bool,
):
    # Create an SSL context
    context = ssl.create_default_context()

    # Create a socket to connect to the server
    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            # Get the server's certificate
            cert = ssock.getpeercert()

            # Extract the expiration and issuance dates from the certificate
            exp_date = datetime.datetime.strptime(
                cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
            )
            issue_date = datetime.datetime.strptime(
                cert["notBefore"], "%b %d %H:%M:%S %Y %Z"
            )

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

            # Print the certificate info based on the provided command-line arguments
            if print_all or print_cert_expiry:
                print("Certificate expires on:", exp_date)
            if print_all or print_issue_date:
                print("Certificate was issued on:", issue_date)
            if print_all or print_days_to_expiry:
                print("Days until certificate expiry:", days_until_expiry)
            if print_all or print_tls_version:
                print("TLS version:", tls_version)
            if print_all or print_ciphers_used:
                print("Ciphers used:", ciphers)
            if print_all or print_issuer_info:
                print(f"Issuer: {org_name}, {common_name}, {country_name}")


if __name__ == "__main__":
    # Define command-line arguments
    parser = argparse.ArgumentParser(description="Check SSL/TLS certificate info")
    parser.add_argument("hostname", type=str, help="hostname of the server to check")
    parser.add_argument("port", type=int, help="port number of the server to check")
    parser.add_argument("--all", action="store_true", help="print all information")
    parser.add_argument(
        "--expiry", action="store_true", help="print certificate expiry date"
    )
    parser.add_argument(
        "--issue", action="store_true", help="print certificate issuance date"
    )
    parser.add_argument(
        "--days", action="store_true", help="print days until certificate expiry date"
    )
    parser.add_argument("--tls", action="store_true", help="print TLS version")
    parser.add_argument("--ciphers", action="store_true", help="print ciphers used")
    parser.add_argument(
        "--issuer", action="store_true", help="print certificate issuer information"
    )

    args = parser.parse_args()

    if not any(
        [args.expiry, args.issue, args.days, args.tls, args.ciphers, args.issuer]
    ):
        args.all = True

    print_ssl_info(
        args.hostname,
        args.port,
        args.all,
        args.expiry,
        args.issue,
        args.days,
        args.tls,
        args.ciphers,
        args.issuer,
    )
