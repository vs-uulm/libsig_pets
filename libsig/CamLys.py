from libsig.AbstractSignatureScheme import AbstractSignatureScheme
from libsig.primes import gen_prime, is_safe_prime
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
    @staticmethod
    def generate_new_keys(size=1024):
        p = gen_prime(size, extra_check=is_safe_prime)
        q = gen_prime(size, extra_check=is_safe_prime)
        return BasicCamLysParams(p, q)

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

        self._a = self._gen_quad_remainder()
        self._b = self._gen_quad_remainder()
        self._c = self._gen_quad_remainder()

        self._l = l

    def _gen_quad_remainder(self):
        return gm.powmod(mpz(secrets.randbits(self.bits)), 2, self.modulus)

    def _make_sign_params(self, message, l=160):
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
        return self._q.bit_length()

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


safe_prime_1 = mpz(165195723491320276070781388314661969203850281718474434373244184377255543234989828926944838604093072094712871850499619593790369229388254520118976785865223757486364945116449578212404927018534927095601779387234560717995901634286739274946633445438628068352786244592876000571239397727491516595455177480353611868067)
safe_prime_2 = mpz(157862269064439940228510655717005367172381033749718149478446373827553460462372923061777429784196645698005719895063367235052595100578207083662396149553997181007483299532237781653582133926154327260332752894466253219361896539391167392180730877701203825832727693064276062112645179588487253289166027092860869897619)


class BasicCamLys(AbstractSignatureScheme):
    """this just binds the real deal to the unfit interface o_0

    it is capable of signing one hashed message.
    >>> bcl = BasicCamLys.keygen()
    >>> message = str.encode("Star wars is awesome")
    >>> signature = BasicCamLys.sign(bcl, message)
    >>> BasicCamLys.verify(bcl, message, signature)
    True
    """
    _BCL = BasicCamLysParams(safe_prime_1, safe_prime_2)

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
