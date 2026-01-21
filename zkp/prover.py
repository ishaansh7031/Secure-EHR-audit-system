import hashlib
import random

def fiat_shamir_prove(secret: int, p: int, g: int):
    # Prover: knows secret x, wants to prove knowledge of x s.t. g^x mod p = y
    x = secret
    y = pow(g, x, p)  # public

    r = random.randint(1, p - 1)
    t = pow(g, r, p)  # commitment

    c = int(hashlib.sha256(str(t).encode()).hexdigest(), 16) % p  # challenge

    s = (r + c * x) % (p - 1)  # response

    return {
        "t": t,
        "c": c,
        "s": s,
        "y": y,
        "p": p,
        "g": g
    }
