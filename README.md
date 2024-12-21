# PKCS#11 Example with Python

This project demonstrates how to use PKCS#11 with Python for cryptographic operations such as signing, verifying, encrypting, and decrypting data.

## Prerequisites

- Python 3.x
- A PKCS#11 library (e.g., SoftHSM)
- The following Python modules:
  - `pycryptodome`
  - `python-pkcs11`

## Installation

1. Install the required Python modules:

    ```sh
    pip install pycryptodome python-pkcs11
    ```

2. Set up your PKCS#11 library (e.g., SoftHSM) and configure it properly.

## Usage

1. Set the `PKCS11_MODULE_PATH` environment variable to the path of your PKCS#11 library:

    ```sh
    export PKCS11_MODULE_PATH=/path/to/your/pkcs11/library.so
    ```

2. Run the script:

    ```sh
    python pkcs11-test.py
    ```

## Functions

- `parse_pkcs11_uri(uri)`: Parses a PKCS#11 URI into a dictionary.
- `pkcs11_sign(key_uri, pin, data)`: Signs data using a private key specified by the PKCS#11 URI.
- `pkcs11_verify(key_uri, pin, data, signature)`: Verifies a signature using a public key specified by the PKCS#11 URI.
- `pkcs11_encrypt(key_uri, pin, ivt, data)`: Encrypts data using a secret key specified by the PKCS#11 URI.
- `pkcs11_decrypt(key_uri, pin, ivt, data)`: Decrypts data using a secret key specified by the PKCS#11 URI.

## Example

```python
key_uri = "pkcs11:token=token0;object=testkeyECp256"
data = b"Hello, world!"
signature = pkcs11_sign(key_uri, "12345", data)
pkcs11_verify(key_uri, "12345", data, signature)

aes_key_uri = "pkcs11:token=token0;object=testkeyAES256"
ivt = os.urandom(16).hex()
data_encrypt = pkcs11_encrypt(aes_key_uri, "12345", ivt, data)
data_decrypt = pkcs11_decrypt(aes_key_uri, "12345", ivt, data_encrypt)
print(data_decrypt)

