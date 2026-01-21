def fiat_shamir_verify(proof: dict) -> bool:
    t = proof["t"]
    c = proof["c"]
    s = proof["s"]
    y = proof["y"]
    p = proof["p"]
    g = proof["g"]

    left = pow(g, s, p)
    right = (t * pow(y, c, p)) % p

    return left == right
