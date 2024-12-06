# -----------------------------------------------------------------------
# SP24 CMPSC 360 Extra Credit Assignment 2
# RSA Implementation
# 
# Name: Jacob Gavin
# ID: 945324828
# 
# 
# You cannot use any external/built-in libraries to help compute gcd
# or modular inverse. You cannot use RSA, cryptography, or similar libs
# for this assignment. You must write your own implementation for generating
# large primes. You must wirte your own implementation for modular exponentiation and
# modular inverse.
# 
# You are allowed to use randint from the built-in random library
# -----------------------------------------------------------------------

from typing import Tuple
import random
import math

# Type defs
Key = Tuple[int, int]
ASCII_MIN = 32
ASCII_MAX = 128
BASE = ASCII_MAX - ASCII_MIN + 1 # will be set to 97



#Helper functions
def gcd(a: int, b: int):
    while b!=0:
        a, b = b, a % b
    return a

def extended_gcd(a: int, b:int):
    if b == 0:
        return (a, 1, 0)
    else:
        g, x, y = extended_gcd(b,a % b)
        return (g, y, x - (a // b) * y)

def inverse_mod(e: int, phi: int) -> int:
    g, x, _ = extended_gcd(e, phi)
    if g != 1:
        raise ValueError("no inverse")
    return x % phi
    
def mod_exp(base: int, exponent: int, modulus: int) -> int:
    result = 1
    base = base % modulus
    while exponent > 0:
        if exponent & 1:
            result = (result * base) % modulus
            
        exponent >>= 1
        base = (base * base) % modulus
    return result

def miller_rabin(d: int, n: int) -> bool:
    a = random.randint(2, n-2)
    x = mod_exp(a, d, n)
    if x == 1 or x == n - 1:
        return True
    while d != n - 1:
        x = (x * x) % n
        d <<= 1
        if x == 1:
            return False
        if x == n - 1:
            return True
    return False

def is_prime(n: int, k: int = 10) -> bool:
    if n <= 1 or n == 4:
        return False
    if n <= 3:
        return True
    d = n - 1
    while d % 2 == 0:
        d //= 2

    for _ in range(k):
        if not miller_rabin(d,n):
            return False
    return True


def generate_prime(n: int) -> int:
    '''
    Description: Generate an n-bit prime number
    Args: n (No. of bits)
    Returns: prime number
    
    NOTE: This needs to be sufficiently fast or you may not get
    any credit even if you correctly return a prime number.
    '''
    while True:
        candidate = ( 1 << (n - 1)) | random.getrandbits(n-1)
        candidate |= 1
        if is_prime(candidate):
            return candidate




def generate_keypair(p: int, q: int) -> Tuple[Key, Key]:
    '''
    Description: Generates the public and private key pair
    if p and q are distinct primes. Otherwise, raise a value error
    
    Args: p, q (input integers)

    Returns: Keypair in the form of (Pub Key, Private Key)
    PubKey = (n,e) and Private Key = (n,d)
    '''
    if p == q or not is_prime(p) or not is_prime(q):
        raise ValueError("P and Q must be distinct prime")
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    if gcd(e, phi) != 1:
        e = 3
        while gcd(e, phi) != 1:
            e += 2
    d = inverse_mod(e, phi)

    return (n, e), (n, d)



def rsa_encrypt(m: str, pub_key: Key, blocksize: int) -> int:
    '''
    Description: Encrypts the message with the given public
    key using the RSA algorithm.

    Args: m (input string)

    Returns: c (encrypted cipher)
    NOTE: You CANNOT use the built-in pow function (or any similar function)
    here.
    '''
    (n, e) = pub_key
    chunks = [m[i:i+blocksize] for i in range(0, len(m), blocksize)]
   
    if len(chunks[-1]) < blocksize:
        chunks[-1] += ' ' * (blocksize - len(chunks[-1]))

  
    encrypted_chunks = []
    for chunk in chunks:
        num = chunk_to_num(chunk)
        c = mod_exp(num, e, n)
        encrypted_chunks.append(c)

    cipher_base = n + 1
    ciphertext = 0
    for c in encrypted_chunks:
        ciphertext = ciphertext * cipher_base + c

    return ciphertext


def rsa_decrypt(c: str, priv_key: Key, blocksize: int) -> int:
    '''
    Description: Decrypts the ciphertext using the private key
    according to RSA algorithm

    Args: c (encrypted cipher string)

    Returns: m (decrypted message, a string)
    NOTE: You CANNOT use the built-in pow function (or any similar function)
    here.
    '''
    (n, d) = priv_key
    ciphertext = int(c)
    cipher_base = n + 1

    enc_chunks = []
    while ciphertext > 0:
        c_chunk = ciphertext % cipher_base
        ciphertext //= cipher_base
        enc_chunks.append(c_chunk)
    enc_chunks.reverse()

    plaintext_chunks = []
    for c_chunk in enc_chunks:
        mnum = mod_exp(c_chunk, d, n)
        chunk = num_to_chunk(mnum, blocksize)
        plaintext_chunks.append(chunk)

    plaintext = "".join(plaintext_chunks).rstrip()

    plaintext_num = 0
    for ch in plaintext:
        val = ord(ch) - ASCII_MIN
        plaintext_num = plaintext_num * BASE + val

    return plaintext_num
def chunk_to_num( chunk ):
    '''
    Description: Convert chunk (substring) to a unique number mod n^k
    n is the common modulus, k is length of chunk.

    Args: chunk (a substring of some messages)

    Returns: r (some integer)
    NOTE: You CANNOT use any built-in function to implement base conversion. 
    '''
    num = 0
    for ch in chunk:
        val = ord(ch) - ASCII_MIN
        num = num * BASE + val
    return num


def num_to_chunk( num, chunksize ):
    '''
    Description: Convert a number back to a chunk using a given 
    chunk size

    Args: num (integer), chunksize (integer)

    Returns: chunk (some substring)
    NOTE: You CANNOT use any built-in function to implement base conversion. 
    '''
    chars = []
    for _ in range(chunksize):
        val = num % BASE
        num //= BASE
        chars.append(chr(val + ASCII_MIN))
    chars.reverse()
    return ''.join(chars)


if __name__ == "__main__":
    # small test
    p = generate_prime(16)  # very small prime for testing
    q = generate_prime(16)
    while q == p:
        q = generate_prime(16)

    pub_key, priv_key = generate_keypair(p, q)

    message = "Hello World!"
    blocksize = 2
    encrypted_int = rsa_encrypt(message, pub_key, blocksize)
    decrypted_int = rsa_decrypt(str(encrypted_int), priv_key, blocksize)

    print("Original Message:", message)
    print("Encrypted Integer:", encrypted_int)
    print("Decrypted Integer:", decrypted_int)
    # If we want to verify, we can convert decrypted_int back to string:
    # Convert decrypted_int back to string:
    def int_to_str(num: int) -> str:
        # reverse of chunk_to_num for entire message
        chars = []
        while num > 0:
            val = num % BASE
            num //= BASE
            chars.append(chr(val + ASCII_MIN))
        chars.reverse()
        return ''.join(chars)

    recovered_message = int_to_str(decrypted_int)
    print("Recovered Message:", recovered_message)
