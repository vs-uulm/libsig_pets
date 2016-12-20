from libsig.AbstractSignatureScheme import AbstractSignatureScheme
import gmpy
import random
import hashlib

class RSAsig(AbstractSignatureScheme):
    """This class implements the well known RSA-signature scheme.
    
    >>> (pubkey, privkey) = RSAsig.keygen()
    >>> message = str.encode("Star wars is awesome")
    >>> signature = RSAsig.sign(privkey, message)
    >>> RSAsig.verify(pubkey, message, signature)
    True
    >>> RSAsig.verify(pubkey, message, signature+1)
    False
    """
    @staticmethod
    def keygen():
	# generate the primes
        p = random.SystemRandom().getrandbits(1024)
        p = int(gmpy.next_prime(p))
        q = random.SystemRandom().getrandbits(1024)
        q = int(gmpy.next_prime(q))
        n = p*q 
        e = 65537
        d = gmpy.invert(e, (p-1)*(q-1))
        pubkey = (e,n)
        privkey = (d,n)
        return (pubkey, privkey)

    @staticmethod
    def sign(privkey, message):
        """returns a signature."""
        (d,n) = privkey
        hash_as_int = int.from_bytes(hashlib.sha256(message).digest(), 'little')
        return pow(hash_as_int, d, n)

    @staticmethod
    def verify(pubkey, message, signature):
        """returns True iff the signature is correct."""
        (e,n) = pubkey
        hash_as_int = int.from_bytes(hashlib.sha256(message).digest(), 'little')
        return pow(signature, e, n) == hash_as_int
