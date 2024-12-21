#!/usr/bin/env python3

import os
import re
import pkcs11
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from pkcs11 import KeyType, ObjectClass, Mechanism
from pkcs11.util.ec import encode_ec_public_key
from urllib.parse import urlparse, parse_qs, unquote

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


def sign_data_with_pkcs11(key_uri, pin, data):
    pkcs11_dict = parse_pkcs11_uri(key_uri)
    lib = pkcs11.lib(os.environ['PKCS11_MODULE_PATH'])
    token = lib.get_token(token_label=pkcs11_dict['token'])

    # Open a session on our token
    with token.open(user_pin=pin) as session:
        # Find the private key object
        privkey  = session.get_key(label=pkcs11_dict['object'], key_type=KeyType.EC, object_class=ObjectClass.PRIVATE_KEY)
        # Sign

        sha256 = SHA256.new(data).digest()
        signature = privkey.sign(sha256, mechanism=Mechanism.ECDSA)

    return signature

def verify_data_with_pkcs11(key_uri, pin, signature, data):
    pkcs11_dict = parse_pkcs11_uri(key_uri)
    lib = pkcs11.lib(os.environ['PKCS11_MODULE_PATH'])
    token = lib.get_token(token_label=pkcs11_dict['token'])

    # Open a session on our token
    with token.open(user_pin=pin) as session:
        # Find the private key object
        pubkey  = session.get_key(label=pkcs11_dict['object'], key_type=KeyType.EC, object_class=ObjectClass.PUBLIC_KEY)
        # Verify
        verifier = DSS.new(ECC.import_key(encode_ec_public_key(pubkey)), 'fips-186-3')
        sha256 = SHA256.new(data)
        try:
            verifier.verify(sha256, signature)
            print('The signature is valid.')

        except ValueError:
            print('The signature is not valid.')

def encrypt_data_with_pkcs11(key_uri, pin, ivt, data):
    pkcs11_dict = parse_pkcs11_uri(key_uri)
    lib = pkcs11.lib(os.environ['PKCS11_MODULE_PATH'])
    token = lib.get_token(token_label=pkcs11_dict['token'])

    # Open a session on our token
    with token.open(user_pin=pin) as session:
        # Find the private key object
        key = session.get_key(label=pkcs11_dict['object'], key_type=KeyType.AES, object_class=ObjectClass.SECRET_KEY)
        # Encrypt

        data_encrypt = key.encrypt(data, mechanism_param=bytes.fromhex(ivt), mechanism=Mechanism.AES_CBC_PAD)

    return data_encrypt

def decrypt_data_with_pkcs11(key_uri, pin, ivt, data):
    pkcs11_dict = parse_pkcs11_uri(key_uri)
    lib = pkcs11.lib(os.environ['PKCS11_MODULE_PATH'])
    token = lib.get_token(token_label=pkcs11_dict['token'])

    # Open a session on our token
    with token.open(user_pin=pin) as session:
        # Find the private key object
        key = session.get_key(label=pkcs11_dict['object'], key_type=KeyType.AES, object_class=ObjectClass.SECRET_KEY)
        # Encrypt

        data_decrypt = key.decrypt(data, mechanism_param=bytes.fromhex(ivt), mechanism=Mechanism.AES_CBC_PAD)

    return data_decrypt

def main():
    key_uri = "pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=dbc936d64a10392e;token=token0;id=%66;object=testkeyECp256;type=private"
    print(parse_pkcs11_uri(key_uri))
    print(parse_pkcs11_uri(key_uri)['model'])
    print(parse_pkcs11_uri(key_uri)['manufacturer'])
    print(parse_pkcs11_uri(key_uri)['token'])
    print(parse_pkcs11_uri(key_uri)['id'].encode('utf-8').hex())
    print(parse_pkcs11_uri(key_uri)['object'])
    print(parse_pkcs11_uri(key_uri)['type'])

    data = b"Hello, world!"
    signature = sign_data_with_pkcs11(key_uri, "12345", data)
    verify_data_with_pkcs11(key_uri, "12345", signature, data)

    key_uri = "pkcs11:token=token0;object=testkeyAES256"
    ivt = os.urandom(16).hex()
    data_encrypt= encrypt_data_with_pkcs11(key_uri, "12345", ivt, data)
    data_decrypt = decrypt_data_with_pkcs11(key_uri, "12345", ivt, data_encrypt)
    print(data_decrypt)

if __name__ == "__main__":
    main()