"""
    The specific script checks if the given url certificate is in X_509 valid.
"""
import os
import ssl
import socket
import argparse
import OpenSSL
from datetime import datetime


def get_certificate(host, port=443, timeout=10):
    """

    Getting Certificate for specific host

    Args:
        host (str): Url to check certificate
        port (int) default = 443: Port number for the communication
        timeout (int) default = 10 : How many seconds to wait for response

    Returns:
        object x509 : Object x509

    """
    context = ssl.create_default_context()
    conn = socket.create_connection((host, port))
    sock = context.wrap_socket(conn, server_hostname=host)
    sock.settimeout(timeout)
    try:
        der_cert = sock.getpeercert(True)
    finally:
        sock.close()
    return ssl.DER_cert_to_PEM_cert(der_cert)


def parse_arguments() -> argparse.Namespace :
    """
    Handling and parsing the command line arguments
    Returns:
        [argparse.Namespace]: The parsed arguments
    """
    example_usage = """Example of use:
        python3 certificate_checker.py -u google.com -i known_issuers.txt"""
    parser = argparse.ArgumentParser(description="Certification checking",
                                     epilog=example_usage,
                                     formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument("-u", "--url", required=True,
                        help="Input url")
    parser.add_argument("-i", "--issuers", required=True,
                        help="Known Issuers")

    return parser.parse_args()


def get_known_issuers(issuers:str) -> list:
    """
    Reading known issuers from txt file

    Args:
        issuers (str): Known issuers file path
    Returns:
        known_issuers (list): The known issuers in a list
    """
    known_issuers = []
    with open(issuers, 'r') as f :
        for line in f:
            known_issuers.append(line.rstrip("\n"))
    return known_issuers


def main(url:str, issuers:str):
    """
    Main function

    Args:
        url (str): Url to check certification
    """
    certificate = get_certificate(url)
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate)
    result = {
        'issuer': dict(x509.get_issuer().get_components()),
        'serialNumber': x509.get_serial_number(),
        'version': x509.get_version(),
        'notBefore':datetime.strptime(x509.get_notBefore().decode('ascii'), "%Y%m%d%H%M%SZ"),
        'notAfter': datetime.strptime(x509.get_notAfter().decode('ascii'), "%Y%m%d%H%M%SZ")
    }

    
    today = datetime.now()
    if today < result['notAfter']:
        print(f'Certificate for {url} is not expired')
        o = result["issuer"][b'O']
        known_issuers = get_known_issuers(issuers)
        if o.decode("utf-8") in known_issuers:
            print("Issuer was found in known issuers, certificate is valid")
            print("Certificate info:")
            print("\tSerial number:", result['serialNumber'])
            print("\tIs valid till:", result['notAfter'])
            print("\tIs going to expired on:", result['notAfter'] - today)
            print("\tIssuer is:", o.decode("utf-8"))
        else:
            print("Issuer not found in known issuers, not valid certificate")
    else:
        diff = result["notAfter"] - today
        print(f'Certificate for {url} have been expired for {diff}')



	


if __name__ == "__main__":
    parser = parse_arguments()
    input_url = parser.url
    issuers = parser.issuers
    if not os.path.isfile(issuers):
        raise Exception(f'{issuers} file path not found!')
    main(input_url, issuers)
