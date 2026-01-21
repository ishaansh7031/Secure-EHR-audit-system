import json
from Crypto.Cipher import AES
from key_manager import KeyManager

class AuditorClient:
    def __init__(self, my_id: str, rsa_priv, server_pub):
        self.my_id     = my_id
        self.rsa_priv  = rsa_priv
        self.server_pub = server_pub

    def process(self, records: list[dict]) -> list[dict]:
        """
        Given a list of ordered records (as dicts), verify the chain and
        decrypt each payload for this auditor. Returns list of plaintext dicts.
        """
        plaintexts = []
        prev_rec = None

        for rec in records:
            # 1. Verify prev_sig matches previous record
            if prev_rec:
                expected = prev_rec["sig"]
                if rec.get("prev_sig") != expected:
                    raise ValueError(f"Chain break at seq {rec['seq']}")

            # 2. Verify this record's signature
            rec_copy = {k:v for k,v in rec.items() if k!="sig"}
            rec_bytes = json.dumps(rec_copy, sort_keys=True, separators=(',',':')).encode()
            KeyManager.verify(rec_bytes, bytes.fromhex(rec["sig"]), self.server_pub)

            # 3. Unwrap AES key & decrypt
            wrapped = bytes.fromhex(rec["wrappings"][self.my_id])
            aes_key = KeyManager.unwrap_key(wrapped, self.rsa_priv)

            cipher = AES.new(aes_key, AES.MODE_GCM, nonce=bytes.fromhex(rec["nonce"]))
            pt = cipher.decrypt_and_verify(bytes.fromhex(rec["cipher"]),
                                           bytes.fromhex(rec["tag"]))
            plaintexts.append(json.loads(pt.decode()))

            prev_rec = rec

        return plaintexts
