from ecdsa import SigningKey, VerifyingKey, SECP256k1
from hashlib import sha256

sk = SigningKey.generate(curve=SECP256k1)
vk = sk.verifying_key
with open("private.pem", "wb") as f:
    f.write(sk.to_pem())
with open("public.pem", "wb") as f:
    f.write(vk.to_pem())


def main():
    print("test")

if __name__ == "__main__" :
    main()