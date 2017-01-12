from libsig.AbstractSignatureScheme import AbstractSignatureScheme
from libsig.primes import gen_prime, is_safe_prime
from libsig import primes
import gmpy2 as gm
from gmpy2 import mpz
from hashlib import sha256
from libsig import secrets  # compat to 3.5


class BasicCamLysParams:
    """This class implements the basic signature scheme from
    "A Signature Scheme with Efficient Protocols"
    Jan Camenisch and Anna Lysyanskaya
    http://dx.doi.org/10.1007/3-540-36413-7_20

    >>> bcl = BasicCamLysParams.generate_new_keys(512)  # 512 is not big enough, but 1024 takes a long time to generate
    >>> message = str.encode("Star wars is awesome")
    >>> signature = bcl.sign(message)
    >>> e, s, v = signature
    >>> bcl.verify(e, s, v, message)
    True
    >>> bcl.verify(e+2, s, v, message)
    False
    >>> bcl.verify(e, s+1, v, message)
    False
    >>> bcl.verify(e, s, v+1, message)
    False
    """
    @classmethod
    def generate_new_keys(cls, size=1024):
        p = gen_prime(size, extra_check=is_safe_prime)
        q = gen_prime(size, extra_check=is_safe_prime)
        return cls(p, q)

    def __init__(self, p, q, l=160):
        if not gm.is_prime(p//2):
            raise ValueError("primes must be safe and p is not, invalid parameters")

        if not gm.is_prime(p//2):
            raise ValueError("primes must be safe and p is not, invalid parameters")

        if not p.bit_length() == q.bit_length():
            raise ValueError("primes must be equal in length, invalid parameters")

        self._p = p
        self._q = q
        self._n = p*q

        self._a = self._gen_quad_residue()
        self._b = self._gen_quad_residue()
        self._c = self._gen_quad_residue()

        self._l = l

    def _gen_quad_residue(self):
        return gm.powmod(mpz(secrets.randbits(self.bits)), 2, self.modulus)

    def _make_sign_params(self, message):
        m = hash_message_as_int(message)

        ln = gm.bit_length(self.modulus)
        lm = gm.bit_length(m)
        le = lm+2
        ls = lm + ln + self.l

        e = gen_prime(le, secret_prime=False)
        s = secrets.randbits(ls)
        s = gm.bit_set(s, ls-1)

        return e, m, s

    @property
    def modulus(self):
        return self._n

    @property
    def bits(self):
        return gm.bit_length(self._q)

    @property
    def a(self):
        return self._a

    @property
    def b(self):
        return self._b

    @property
    def c(self):
        return self._c

    @property
    def l(self):
        return self._l

    def calculate_abc(self, message, s):
        return (pow(self.a, message, self.modulus) * pow(self.b, s, self.modulus) * self.c) % self.modulus

    def sign(self, message):
        e, m, s = self._make_sign_params(message)

        d = gm.invert(e, (self._p-1)*(self._q-1))
        pre_v = self.calculate_abc(m, s)
        v = pow(pre_v, d, self.modulus)
        return e, s, v

    def verify(self, e, s, v, message):
        abc = self.calculate_abc(hash_message_as_int(message), s)
        return pow(v, e, self.modulus) == abc


def hash_message_as_int(message, hashfunction=sha256):
    return int(hashfunction(message).hexdigest(), 16)


def multi_powmod(xs, ys, n):
    if len(xs) != len(ys):
        raise ValueError("xs and ys don't have the same size")
    result = 1
    for x, y in zip(xs, ys):
        result = (result * pow(x, y, n)) % n
    return result


class BasicCamLys(AbstractSignatureScheme):
    """this just binds the real deal to the unfit interface o_0

    it is capable of signing one hashed message.
    >>> bcl = BasicCamLys.keygen()
    >>> message = str.encode("Star wars is awesome")
    >>> signature = BasicCamLys.sign(bcl, message)
    >>> BasicCamLys.verify(bcl, message, signature)
    True
    """
    _BCL = BasicCamLysParams(primes.safe_prime_2048_1, primes.safe_prime_2048_2)

    @staticmethod
    def keygen():
        """
        this returns the private and public parameters using the precomputed safe primes

        :return:
        """

        return BasicCamLys._BCL

    @staticmethod
    def sign(privkey, message):
        """returns a signature."""
        return privkey.sign(message)

    @staticmethod
    def verify(pubkey, message, signature):
        """returns True iff the signature is correct."""
        return pubkey.verify(*signature, message)


class BlockCamLysParams(BasicCamLysParams):
    """this just binds the real deal to the unfit interface o_0

    it is capable of signing one hashed message.
    >>> mcl = BlockCamLysParams(primes.safe_prime_1024_1, primes.safe_prime_1024_2, 4)
    >>> messages = [str.encode(message) for message in "Star wars is awesome".split()]
    >>> signature = mcl.sign(messages)
    >>> mcl.verify(*signature, messages)
    True
    """

    def __init__(self, p, q, L):
        super().__init__(p, q)

        del self._a

        self._as = [a for a in self._gen_quad_residues(L)]

    def _gen_quad_residues(self, count):
        for count in range(0, count):
            yield self._gen_quad_residue()

    @property
    def a(self):
        return self._as

    def calculate_abc(self, ms, s):
        result = multi_powmod(self.a + [self.b], ms + [s], self.modulus)
        result = (result * self.c) % self.modulus
        return result

    def sign(self, messages):
        e, ms, s = self._make_sign_params(messages)

        d = gm.invert(e, (self._p-1)*(self._q-1))

        pre_v = self.calculate_abc(ms, s)
        v = pow(pre_v, d, self.modulus)
        return e, s, v

    def verify(self, e, s, v, messages):
        ms = [hash_message_as_int(m) for m in messages]
        abc = self.calculate_abc(ms, s)
        return pow(v, e, self.modulus) == abc

    def _make_sign_params(self, messages):
        if len(messages) != len(self.a):
            raise ValueError("must have %d messages to sign, you provided %d", len(self.a), len(messages) )
        ms = [hash_message_as_int(m) for m in messages]

        ln = gm.bit_length(self.modulus)
        lm = gm.bit_length(ms[0])
        le = lm+2
        ls = lm + ln + self.l

        e = gen_prime(le, secret_prime=False)
        s = secrets.randbits(ls)
        s = gm.bit_set(s, ls-1)

        return e, ms, s


