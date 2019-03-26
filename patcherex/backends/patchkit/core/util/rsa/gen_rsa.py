#!/usr/bin/env python2
import os
import subprocess
import commands

def generate_RSA(bits=2048, e=3):
    '''
    Generate an RSA keypair with an exponent of 3 in PEM format
    param: bits The key length in bits
    Return private key and public key
    '''
    from Crypto.PublicKey import RSA
    new_key = RSA.generate(bits, e=e)
    public_key = new_key.publickey()
    private_key = new_key
    return private_key, public_key

def to_char_arr(n, nbytes=132):
    arr = [0] * nbytes
    for i in range(nbytes):
        arr[i] = int(n % 0x100)
        n /= 0x100
    assert(n == 0)
    return arr

def to_c_arr(n, nbytes=132):
    arr = to_char_arr(n, nbytes)
    return "{ %s }" % ', '.join(map(hex, arr))


if __name__ == "__main__":
    priv, pub = generate_RSA(1024)

    with open("key.c", "w") as f:
        f.write("""// n={n}
// e={e}
// d={d}
uint8_t n[132] = {n_c};
uint8_t d[132] = {d_c};
""".format(n=priv.n, e=priv.e, d=priv.d, n_c=to_c_arr(priv.n), d_c=to_c_arr(priv.d)))

    os.system("make")

    with open("key.pem", "w") as f:
        f.write(priv.exportKey('PEM'))

    subprocess.check_call(["python", "./rsa.py"])
