#!/usr/bin/env python3

import os
import re
import pkcs11
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC, RSA
from Crypto.Signature import DSS, PKCS1_v1_5
from pkcs11 import KeyType, ObjectClass, Mechanism
from pkcs11.util.ec import encode_ec_public_key
from pkcs11.util.rsa import encode_rsa_public_key
from urllib.parse import urlparse, parse_qs, unquote

# Parse a PKCS#11 URI into a dictionary
def parse_pkcs11_uri(uri):
    try:
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
    except Exception as e:
        print(f"Error parsing PKCS#11 URI: {e}")
        raise

def pkcs11_sign(key_uri, pin, data):
    try:
        pkcs11_dict = parse_pkcs11_uri(key_uri)
        lib = pkcs11.lib(os.environ['PKCS11_MODULE_PATH'])
        token = lib.get_token(token_label=pkcs11_dict['token'])

        # Open a session on our token
        with token.open(user_pin=pin) as session:
            # Find the private key object
            privkey = session.get_key(label=pkcs11_dict['object'], object_class=ObjectClass.PRIVATE_KEY)
            if privkey.key_type == KeyType.RSA:
                mech = Mechanism.RSA_PKCS
            elif privkey.key_type == KeyType.EC:
                mech = Mechanism.ECDSA
            else:
                raise ValueError("Unsupported key type")
            # Sign
            sha256 = SHA256.new(data).digest()
            signature = privkey.sign(sha256, mechanism=mech)

        return signature
    except Exception as e:
        print(f"Error signing data: {e}")
        raise

def pkcs11_verify(key_uri, pin, data, signature):
    try:
        pkcs11_dict = parse_pkcs11_uri(key_uri)
        lib = pkcs11.lib(os.environ['PKCS11_MODULE_PATH'])
        token = lib.get_token(token_label=pkcs11_dict['token'])

        # Open a session on our token
        with token.open(user_pin=pin) as session:
            # Find the private key object
            pubkey  = session.get_key(label=pkcs11_dict['object'], object_class=ObjectClass.PUBLIC_KEY)
            if pubkey.key_type == KeyType.RSA:
                verifier = PKCS1_v1_5.new(RSA.import_key(encode_rsa_public_key(pubkey)))
            elif pubkey.key_type == KeyType.EC:
                verifier = DSS.new(ECC.import_key(encode_ec_public_key(pubkey)), 'fips-186-3')
            else:
                raise ValueError("Unsupported key type")
            # Verify
            sha256 = SHA256.new(data)
            try:
                verifier.verify(sha256, signature)
                print('The signature is valid.')
            except ValueError:
                print('The signature is not valid.')
    except Exception as e:
        print(f"Error verifying signature: {e}")
        raise

def pkcs11_encrypt(key_uri, pin, ivt, data):
    try:
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
    except Exception as e:
        print(f"Error encrypting data: {e}")
        raise

def pkcs11_decrypt(key_uri, pin, ivt, data):
    try:
        pkcs11_dict = parse_pkcs11_uri(key_uri)
        lib = pkcs11.lib(os.environ['PKCS11_MODULE_PATH'])
        token = lib.get_token(token_label=pkcs11_dict['token'])

        # Open a session on our token
        with token.open(user_pin=pin) as session:
            # Find the private key object
            key = session.get_key(label=pkcs11_dict['object'], key_type=KeyType.AES, object_class=ObjectClass.SECRET_KEY)
            # Decrypt
            data_decrypt = key.decrypt(data, mechanism_param=bytes.fromhex(ivt), mechanism=Mechanism.AES_CBC_PAD)

        return data_decrypt
    except Exception as e:
        print(f"Error decrypting data: {e}")
        raise

def main():
    try:
        key_uri = "pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=c298aee2f10d4361;token=token0;id=%62;object=testkeyECp256;type=public"
        print(parse_pkcs11_uri(key_uri))
        print(parse_pkcs11_uri(key_uri)['model'])
        print(parse_pkcs11_uri(key_uri)['manufacturer'])
        print(parse_pkcs11_uri(key_uri)['token'])
        print(parse_pkcs11_uri(key_uri)['id'].encode('utf-8').hex())
        print(parse_pkcs11_uri(key_uri)['object'])
        print(parse_pkcs11_uri(key_uri)['type'])

        ec_key_uri = "pkcs11:token=token0;object=testkeyECp256"
        data = b"Hello, world!"
        signature = pkcs11_sign(ec_key_uri, "12345", data)
        pkcs11_verify(ec_key_uri, "12345", data, signature)

        rsa_key_uri = "pkcs11:token=token0;object=testkeyRSA2048"
        data = b"Hello, world!"
        signature = pkcs11_sign(rsa_key_uri, "12345", data)
        pkcs11_verify(rsa_key_uri, "12345", data, signature)

        aes_key_uri = "pkcs11:token=token0;object=testkeyAES256"
        ivt = os.urandom(16).hex()
        data_encrypt = pkcs11_encrypt(aes_key_uri, "12345", ivt, data)
        data_decrypt = pkcs11_decrypt(aes_key_uri, "12345", ivt, data_encrypt)
        print(data_decrypt)
    except Exception as e:
        print(f"Error in main: {e}")

if __name__ == "__main__":
    main()