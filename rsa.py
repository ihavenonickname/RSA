class RSAKeyPair():
    def __init__(self, exponent, mod):
        self.exponent = exponent
        self.mod = mod

# Knuth in "The art of computer programming" introduced this algorithm for
# finding 1/u mod v where both u and v are positive.
def modinv(u, v):
    u1 = 1
    u3 = u
    v1 = 0
    v3 = v

    is_even_iter = False

    while v3:
        q = u3 // v3
        t3 = u3 % v3
        t1 = u1 + q * v1

        u1 = v1
        v1 = t1
        u3 = v3
        v3 = t3

        is_even_iter = not is_even_iter

    if u3 != 1:
        return 0

    if is_even_iter:
        return v - u1

    return u1

def generate_rsa_keys(p, q):
    # https://en.wikipedia.org/wiki/Euler%27s_totient_function
    # Counts how many coprimes are there between 1 and n (see n below).
    phi = (p - 1) * (q - 1)

    # The bit length of n is the bit length of the encrypted values.
    n = p * q

    # This is the public exponent. It's a cool prime number that makes
    # exponentiation very fast -- only 2 bits are set.
    e = 65537

    # This is the private exponent. It's a modular inverse of the public key. In
    # order to derive d from e attackers need to factorize p and q, which is
    # currently a fairly expandive operation.
    d = modinv(e, phi)

    public_key = RSAKeyPair(exponent=e, mod=n)
    private_key = RSAKeyPair(exponent=d, mod=n)

    return public_key, private_key

def encrypt(value, key_pair):
    return pow(value, key_pair.exponent, key_pair.mod)

def main():
    # Two arbitrary primes.
    public_key, private_key = generate_rsa_keys(23, 29)

    # A value not greater than mod.
    original_value = 42

    encripted = encrypt(original_value, public_key)
    decripted = encrypt(encripted, private_key)

    print(original_value, encripted, decripted)

if __name__ == '__main__':
    main()
