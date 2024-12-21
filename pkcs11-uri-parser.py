#!/usr/bin/env python3
from urllib.parse import urlparse, parse_qs, unquote
import re

# Parse a PKCS#11 URI into a dictionary
def parse_pkcs11_uri(uri):
    parsed_uri = urlparse(uri)
    if parsed_uri.scheme != 'pkcs11':
        raise ValueError("Invalid PKCS#11 URI scheme")

    # Extract the path component and split by ';'
    path = unquote(parsed_uri.path)
    path_components = path.split(';')

    # Parse the path components into a dictionary
    path_dict = {}
    for component in path_components:
        if '=' in component:
            key, value = component.split('=', 1)
            value = unquote(value)
            path_dict[key] = value

    # Parse the query components into a dictionary
    query_dict = parse_qs(parsed_uri.query)

    pkcs11_dict = {**path_dict, **{k: v[0] for k, v in query_dict.items()}}

    return pkcs11_dict

def main():
    # Example usage
    pkcs11_uri = "pkcs11:model=PKCS%2315%20emulated;manufacturer=www.CardContact.de;serial=DENK0102042;token=SmartCard-HSM%20%28UserPIN%29;id=%01;object=testkeyECp256;type=private"
    print(parse_pkcs11_uri(pkcs11_uri))
    print(parse_pkcs11_uri(pkcs11_uri)['model'])
    print(parse_pkcs11_uri(pkcs11_uri)['manufacturer'])
    print(parse_pkcs11_uri(pkcs11_uri)['token'])
    print(parse_pkcs11_uri(pkcs11_uri)['id'])
    print(parse_pkcs11_uri(pkcs11_uri)['object'])
    print(parse_pkcs11_uri(pkcs11_uri)['type'])

if __name__ == "__main__":
    main()