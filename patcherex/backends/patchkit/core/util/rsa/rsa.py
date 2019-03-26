import commands
import os
from gen_rsa import to_char_arr
from Crypto.PublicKey import RSA

SECRET_KEY = RSA.importKey(open(os.path.join(os.path.dirname(__file__), "key.pem")).read())

def s2n(s):
    n = 0
    for c in reversed(s):
        n *= 0x100
        n += ord(c)
    return n

def n2s(n):
    m = ""
    while n != 0:
        m += chr(n % 0x100)
        n /= 0x100
    return m

def decrypt(msg):
    return SECRET_KEY.decrypt(msg[::-1])[-120:][::-1].replace("\x00", "")

def raw_n():
    return ''.join(map(chr, to_char_arr(SECRET_KEY.n)))
