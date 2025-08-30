import argparse
import base64

from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError
from hashlib import sha256
import os


# Key Functions
def generate_keys(private_key_path="private.pem", public_key_path="public.pem"):
    """
    Generates a new ECDSA key pair and saves them to the specified files.
    """
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.verifying_key

    # Save the private key to a PEM file
    try:
        with open(private_key_path, "wb") as f:
            f.write(sk.to_pem())
        print(f"✅ Private key saved to: {private_key_path}")

        # Save the public key to a PEM file
        with open(public_key_path, "wb") as f:
            f.write(vk.to_pem())
        print(f"✅ Public key saved to: {public_key_path}")
    except IOError as e:
        print(f"❌ Error: {e}")


def load_private_key(path="private.pem"):
    """
    Loads a private key from a PEM file.
    """
    if not os.path.exists(path):
        print(f"Error: Private key file not found at '{path}'")
        return None
    try:
        with open(path, "rb") as f:
            return SigningKey.from_pem(f.read())
    except Exception as e:
        print(f"❌ Error: {e}")
        return None


def load_public_key(path="public.pem"):
    """
    Loads a public key from a PEM file.
    """
    if not os.path.exists(path):
        print(f"Error: Public key file not found at '{path}'")
        return None
    try:
        with open(path, "rb") as f:
            return VerifyingKey.from_pem(f.read())
    except Exception as e:
        print(f"❌ Error: {e}")
        return None


# Signing and Verification Functions

def sign_message(private_key_path, message):
    """
    Signs a given message using the private key.
    """
    sk = load_private_key(private_key_path)
    if sk:
        # The message must be encoded to bytes before signing
        message_bytes = message.encode('utf-8')
        # Sign the message
        signature = sk.sign(message_bytes)
        # Encode the signature in base64 and print it as a string
        signature_b64 = base64.b64encode(signature).decode('utf-8')
        print(f"✍️ Signature (base64): {signature_b64}")


def verify_signature(public_key_path, signature_base64, message):
    """
    Verifies a signature against a message using the public key.
    """
    vk = load_public_key(public_key_path)
    if vk:
        try:
            # Decode the base64 signature back to bytes
            signature_bytes = base64.b64decode(signature_base64)
            message_bytes = message.encode('utf-8')
            # The verify method will raise BadSignatureError if verification fails
            vk.verify(signature_bytes, message_bytes)
            print("✅ Signature is valid.")
        except BadSignatureError:
            print("❌ INVALID SIGNATURE.")
        except Exception as e:
            print(f"❌ Error: {e}")


# Email Signature and Verification

def verify_signature_email(pub, signature, message):
    """
    Verifies a signature against an email using the public key.
    """
    pass


def sign_email(pub, signature, message):
    """
    signs a given message using the private key.
    """
    pass


def main():
    # main parser
    parser = argparse.ArgumentParser(
        description="A command-line tool to sign and verify messages using ECDSA.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    # subparser to handle generate, sign, ...etc
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    # generate
    parser_generate = subparsers.add_parser("generate", help="Generate a new private/public key pair.")
    parser_generate.add_argument("--priv", default="private.pem",
                                 help="Path to save the private key (default: private.pem)")
    parser_generate.add_argument("--pub", default="public.pem",
                                 help="Path to save the public key (default: public.pem)")

    # sign
    parser_sign = subparsers.add_parser("sign", help="Sign a message with a private key.")
    parser_sign.add_argument("message", help="The message to sign.")
    parser_sign.add_argument("--priv", default="private.pem",
                             help="Path to the private key to use for signing (default: private.pem)")

    # verify
    parser_verify = subparsers.add_parser("verify", help="Verify a signature.")
    parser_verify.add_argument("signature", help="The signature in base64 format.")
    parser_verify.add_argument("message", help="The original message to verify against.")
    parser_verify.add_argument("--pub", default="public.pem",
                               help="Path to the public key to use for verification (default: public.pem)")

    # verify-mail
    parser_verify = subparsers.add_parser("verify-mail",
                                          help="Verify a signature for an email. "
                                               "(ignores whitespace considers only ascii)")
    parser_verify.add_argument("signature", help="The signature in base64 format.")
    parser_verify.add_argument("message", help="The original message to verify against.")
    parser_verify.add_argument("--pub", default="public.pem",
                               help="Path to the public key to use for verification (default: public.pem)")

    # sign-mail
    parser_sign = subparsers.add_parser("sign-mail", help="Sign a email (ignores whitespace considers only ascii)")
    parser_sign.add_argument("message", help="The message to sign.")
    parser_sign.add_argument("--priv", default="private.pem",
                             help="Path to the private key to use for signing (default: private.pem)")

    # Parse the arguments from the command line
    args = parser.parse_args()

    # Execute the corresponding function based on the command
    if args.command == "generate":
        generate_keys(args.priv, args.pub)
    elif args.command == "sign":
        sign_message(args.priv, args.message)
    elif args.command == "verify":
        verify_signature(args.pub, args.signature, args.message)
    elif args.command == "verify-mail":
        verify_signature_email(args.pub, args.signature, args.message)
    elif args.command == "sign-mail":
        sign_email(args.pub, args.signature, args.message)


if __name__ == "__main__":
    main()
