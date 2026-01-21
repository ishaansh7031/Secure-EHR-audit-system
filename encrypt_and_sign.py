import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from key_manager import KeyManager

class AuditRecordBuilder:
    def __init__(self, server_priv, auditor_pubs: dict[str, any]):
        """
        :param server_priv:   RSA private key for signing
        :param auditor_pubs:  map auditor_id → RSA public key
        """
        self.server_priv  = server_priv
        self.auditor_pubs = auditor_pubs
        self.prev_sig     = None
        self.seq          = 0

    def build(self, payload: dict) -> dict:
        # 1. Sequence & timestamp
        self.seq += 1

        # 2. AES-GCM encrypt
        pt    = json.dumps(payload, sort_keys=True).encode()
        key   = get_random_bytes(32)
        nonce = get_random_bytes(12)
        aes   = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ct, tag = aes.encrypt_and_digest(pt)

        # 3. Wrap AES key per auditor
        wrappings = {
            aid: KeyManager.wrap_key(key, pub).hex()
            for aid, pub in self.auditor_pubs.items()
        }

        # 4. Construct the record (no sig yet)
        rec = {
            "seq":       self.seq,
            "nonce":     nonce.hex(),
            "cipher":    ct.hex(),
            "tag":       tag.hex(),
            "wrappings": wrappings
        }
        if self.prev_sig:
            rec["prev_sig"] = self.prev_sig.hex()

        # 5. Canonical JSON + sign
        rec_bytes = json.dumps(rec, sort_keys=True, separators=(',',':')).encode()
        sig       = KeyManager.sign(rec_bytes, self.server_priv)
        rec["sig"] = sig.hex()

        # 6. Chain forward
        self.prev_sig = sig
        return rec
