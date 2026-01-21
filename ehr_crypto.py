import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from key_manager import KeyManager


class EHRCrypto:
    @staticmethod
    def encrypt_ehr(data: dict, rsa_pub) -> dict:
        """
        Encrypt EHR data for a given RSA public key.
        Returns a dict containing ciphertext, nonce, tag, and wrapped AES key.
        """
        # 1. Serialize plaintext
        pt = json.dumps(data, sort_keys=True).encode()

        # 2. Generate AES key and nonce
        aes_key = get_random_bytes(32)
        nonce   = get_random_bytes(12)

        # 3. Encrypt with AES-GCM
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        ct, tag = cipher.encrypt_and_digest(pt)

        # 4. Wrap AES key with recipient's RSA public key
        wrapped_key = KeyManager.wrap_key(aes_key, rsa_pub)

        return {
            "ciphertext": ct.hex(),
            "nonce": nonce.hex(),
            "tag": tag.hex(),
            "wrapped_key": wrapped_key.hex()
        }

    @staticmethod
    def decrypt_ehr(enc_dict: dict, rsa_priv) -> dict:
        """
        Decrypt EHR data using given RSA private key.
        Expects dict with ciphertext, nonce, tag, and wrapped_key.
        """
        # 1. Unwrap AES key
        aes_key = KeyManager.unwrap_key(bytes.fromhex(enc_dict["wrapped_key"]), rsa_priv)

        # 2. Decrypt AES-GCM
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=bytes.fromhex(enc_dict["nonce"]))
        pt = cipher.decrypt_and_verify(
            bytes.fromhex(enc_dict["ciphertext"]),
            bytes.fromhex(enc_dict["tag"])
        )

        return json.loads(pt.decode())
