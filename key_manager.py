from Crypto.PublicKey import RSA
from Crypto.Cipher    import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash      import SHA256
from pathlib import Path

class KeyManager:
    @staticmethod
    def load_public(path: Path) -> RSA.RsaKey:
        return RSA.import_key(path.read_bytes())

    @staticmethod
    def load_private(path: Path) -> RSA.RsaKey:
        return RSA.import_key(path.read_bytes())

    @staticmethod
    def wrap_key(aes_key: bytes, rsa_pub: RSA.RsaKey) -> bytes:
        return PKCS1_OAEP.new(rsa_pub).encrypt(aes_key)

    @staticmethod
    def unwrap_key(wrapped: bytes, rsa_priv: RSA.RsaKey) -> bytes:
        return PKCS1_OAEP.new(rsa_priv).decrypt(wrapped)

    @staticmethod
    def sign(data: bytes, rsa_priv: RSA.RsaKey) -> bytes:
        h = SHA256.new(data)
        return pkcs1_15.new(rsa_priv).sign(h)

    @staticmethod
    def verify(data: bytes, sig: bytes, rsa_pub: RSA.RsaKey):
        h = SHA256.new(data)
        pkcs1_15.new(rsa_pub).verify(h, sig)  # raises ValueError if bad
