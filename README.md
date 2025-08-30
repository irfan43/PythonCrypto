# PythonCrypto

A command-line tool to **sign** and **verify** messages using ECDSA (Elliptic Curve Digital Signature Algorithm) through the Python `ecdsa` library.

## Features

- **Generate ECDSA key pairs**
- **Sign messages** with a private key
- **Verify signatures** with a public key
- Handle email-specific signing and verification (ASCII-only, ignores whitespace; see email commands)


## Installation

Python 3.10+ recommended. 
Install `ecdsa` if not present:

```bash
pip install ecdsa
```

Clone or copy this script.

## Usage

Run the CLI script directly with Python:

```bash
python PythonCrypto.py <command> [options]
```


## Commands

### Generate Key Pair

Generates new ECDSA private and public keys.

```bash
python PythonCrypto.py generate [--priv PRIVATE_KEY_PATH] [--pub PUBLIC_KEY_PATH]
```

- `--priv`: Output path for private key (default: `private.pem`)
- `--pub`: Output path for public key (default: `public.pem`)


### Sign a Message

Signs a message with your private key.

```bash
python PythonCrypto.py sign <message> [--priv PRIVATE_KEY_PATH]
```


### Verify a Signature

Verifies a signature using your public key.

```bash
python PythonCrypto.py verify <signature_base64> <message> [--pub PUBLIC_KEY_PATH]
```


### Email-Specific Commands

(To be implemented)

- **sign-mail:** Signs email messages (ASCII only, ignores whitespace)
- **verify-mail:** Verifies email signatures


## Output

Success and error messages are printed to the console. Signatures are output in Base64 format.

Example:

```
✍️ Signature (base64): <your_signature>
✅ Signature is valid.
❌ INVALID SIGNATURE.
```


## Dependencies

- `ecdsa`
- `argparse` (standard)
- `base64`, `os`, `hashlib` (standard)


## License

GNU GPL-2.0 license

## Contributing

Contributions and improvements are welcome! File issues or pull requests for discussion.
