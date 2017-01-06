from libsig.AbstractSignatureScheme import AbstractSignatureScheme
from libsig.primes import gen_prime
import gmpy as gm
from hashlib import sha256


class RSAsig(AbstractSignatureScheme):
    """This class implements the well known RSA-signature scheme.
    
    >>> (pubkey, privkey, primes) = RSAsig.keygen()
    >>> message = str.encode("Star wars is awesome")
    >>> signature = RSAsig.sign(privkey, message)
    >>> RSAsig.verify(pubkey, message, signature)
    True
    >>> RSAsig.verify(pubkey, message, signature+1)
    False
    >>> gm.bit_length(pubkey[1])
    2048
    >>> gm.bit_length(primes[0])
    1024
    >>> gm.bit_length(primes[1])
    1024
    """
    @staticmethod
    def keygen():
        # generate the primes
        p = int(gen_prime(1024, secret_prime=True, silent=True))
        q = int(gen_prime(1024, secret_prime=True, silent=True))  # this can be sped up, must read more libgcrypt :D
        n = p*q
        e = 65537
        d = gm.invert(e, (p-1)*(q-1))
        pubkey = (e, n)
        privkey = (d, n)
        primes = (p, q)
        return pubkey, privkey, primes

    @staticmethod
    def sign(privkey, message):
        """returns a signature."""
        d, n = privkey
        hash_as_int = int(sha256(message).hexdigest(), 16)
        return pow(hash_as_int, d, n)

    @staticmethod
    def verify(pubkey, message, signature):
        """returns True iff the signature is correct."""
        e, n = pubkey
        hash_as_int = int(sha256(message).hexdigest(), 16)
        return pow(signature, e, n) == hash_as_int
