from libsig.primes import gen_prime, is_safe_prime
from libsig import primes
import gmpy2 as gm
from hashlib import sha256
from libsig import secrets  # compat to 3.5


# util
def hash_message_as_int(message, hashfunction=sha256):
    """
    Hash a message with a chosen hashfunction and return the hash as integer.

    :param message: the encoded message
    :param hashfunction: the hashfunction to use, from python's hashlib or an equivalent
    :return: the message hash as integer
    """
    return int(hashfunction(message).hexdigest(), 16)


def multi_powmod(bases, exponents, modulus):
    """
    raise all bases in xs to the respective powers in ys mod n:
    :math:`\prod_{i=1}^{len(bases)} base_i^{exponent_i} \pmod{modulus}`

    :param bases: the bases
    :param exponents: the exponents
    :param modulus: the modulus
    :return: the calculated result
    """
    if len(bases) != len(exponents):
        raise ValueError("xs and ys don't have the same size")
    result = 1
    for base, power in zip(bases, exponents):
        result = (result * pow(base, power, modulus)) % modulus
    return result


def generate_quadratic_residue(bit_length, modulus):
    """
    By :math:`QR_n \subseteq Z^*_n` we will denote the set of quadratic residues modulo n,
    i.e., elements :math:`a \in Z^*_n` such that :math:`\exists b \in Z^*_n` such that :math:`b^2 \equiv a \pmod{n}`
    This will generate a random quadratic residue chosen from :math:`[0, 2^{bit_length})`

    :param bit_length: the range to choose a random integer from
    :param modulus: the modulus
    :return: a random quadratic residue
    """
    random = secrets.randbits(bit_length)
    return pow(random, 2, modulus)


def generate_quadratic_residues(bit_length, modulus, count):
    """
    generate multiple quadratic residues

    :param bit_length: the range to choose a random integer from
    :param modulus: the modulus
    :param count: how many residues you want to have
    :return: the generator to iterate over
    """
    for count in range(0, count):
        yield generate_quadratic_residue(bit_length, modulus)


class CamLysSignature:
    def __init__(self, e, s, v):
        self.e = e
        self.s = s
        self.v = v


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
        """
        On input :math:`1^k` , choose a special RSA modulus :math:`n = pq, p = 2p' + 1, q = 2q' + 1`
        of the length :math:`l_n = 2k`.

        :param size: size of the primes, k.
        :return: a new instance
        """
        p = gen_prime(size, extra_check=is_safe_prime)
        q = gen_prime(size, extra_check=is_safe_prime)
        return cls(p, q)

    def __init__(self, p, q, hash_function=sha256):
        """
        Choose, uniformly at random, a, b, c ∈ :math:`QR_n` .
        Output PK = (n, a, b, c), and SK = p.

        :param p: a safe prime
        :param q: another safe prime
        :param hash_function: the hash function
        """
        if not gm.is_strong_bpsw_prp(p//2):
            raise ValueError("primes must be safe and p is not, invalid parameters")

        if not gm.is_strong_bpsw_prp(q//2):
            raise ValueError("primes must be safe and q is not, invalid parameters")

        if not p.bit_length() == q.bit_length():
            raise ValueError("primes must be equal in length")

        self._p = p
        self._q = q
        self._n = p*q

        self._hash_function = hash_function

        self._a = generate_quadratic_residue(self.bits, self.modulus)
        self._b = generate_quadratic_residue(self.bits, self.modulus)
        self._c = generate_quadratic_residue(self.bits, self.modulus)

        # security parameter seems to be bound to hash bit length
        # digest_size is in bytes.
        self._l = self._hash_function().digest_size * 8

    @property
    def modulus(self):
        """
        the public modulus n = p*q
        """
        return self._n

    @property
    def bits(self):
        """
        the lenght of the primes, k
        """
        return self._q.bit_length()

    @property
    def a(self):
        """
        the quadratic residue a
       """
        return self._a

    @property
    def b(self):
        """
        the quadratic residue b
        """
        return self._b

    @property
    def c(self):
        """
        the quadratic residue c
        """
        return self._c

    @property
    def l(self):
        """
        the security parameter l.
        """
        return self._l

    @property
    def private_key(self):
        """
        the private key consists of both secret primes p and q

        :return: (p, q)
        """
        return self._p, self._q

    @property
    def public_key(self):
        """
        the public key consists of:
         the modulus n
         and the quadratic residues a, b, c

        :return: (n, a, b, c)
        """
        return self.modulus, self.a, self.b, self.c

    def calculate_abc(self, message, s):
        """
        calculates :math:`a^mb^sc \pmod{n}`

        :param message: the message hash as integer
        :param s: the random number of length :math:`l_n + l_m + l` which normally is bit_length of
                  the modulus and 2*(bit_length of the used hash function)
        :return: the result
        """
        return (pow(self.a, message, self.modulus) * pow(self.b, s, self.modulus) * self.c) % self.modulus

    def make_sign_params(self, message):
        """
        On input m, choose a random prime number e of length :math:`l_e ≥ l_m + 2`,
        and a random number s of length :math:`l_s = l_n + l_m + l`, where l is a security parameter.

        :param message: the unhashed encoded message
        :return: e, int(message_hash), s
        """
        m = hash_message_as_int(message)

        ln = self.modulus.bit_length()
        lm = m.bit_length()
        le = lm+2
        ls = lm + ln + self.l

        e = gen_prime(le, secret_prime=False)
        s = secrets.randbits(ls)
        s = gm.bit_set(s, ls-1)

        return e, m, s

    def sign(self, message):
        """
        Signs a message with:
        Compute the value v such that :math:`v^e ≡ a^mb^sc \pmod{n}`
        see: make_sign_params()

        :param message: the unhashed, encoded message
        :return: the signature: (e, s, v)
        """
        e, m, s = self.make_sign_params(message)

        d = gm.invert(e, (self._p-1)*(self._q-1))
        abc = self.calculate_abc(m, s)
        v = pow(abc, d, self.modulus)
        return e, s, v

    def verify(self, e, s, v, message):
        """
        To verify that the tuple (e, s, v) is a signature on message m in the message space,
        check that :math:`v^e ≡ a^mb^sc \pmod{n}`,
        and check that :math:`2^{l_e} > e > 2^{l_e − 1}`.

        :param e: the exponent used to sign the message
        :param s: the random integer used to sign the message
        :param v: the signature
        :param message: the signed messasge
        :return: True, if the message signature is valid
        """
        m = hash_message_as_int(message)
        le = m.bit_length()+2
        if not (pow(2, le) > e > pow(2, le-1)):
            return False

        abc = self.calculate_abc(m, s)
        return pow(v, e, self.modulus) == abc


class BlockCamLysParams(BasicCamLysParams):
    """Implementation of the CL-RSA for signing Blocks of Messages

    >>> messages = [str.encode(message) for message in "Star wars is boring".split()]
    >>> mcl = BlockCamLysParams(primes.safe_prime_1024_1, primes.safe_prime_1024_2, len(messages))
    >>> signature = mcl.sign(messages)
    >>> mcl.verify(*signature, messages)
    True
    """

    def __init__(self, p, q, L):
        """

        :param p:
        :param q:
        :param L:
        """
        super().__init__(p, q)

        del self._a

        self._as = [a for a in generate_quadratic_residues(self.bits, self.modulus, L)]

    @property
    def a(self):
        return self._as

    def calculate_abc(self, ms, s):
        result = multi_powmod(self.a + [self.b], ms + [s], self.modulus)
        result = (result * self.c) % self.modulus
        return result

    def sign(self, messages):
        e, ms, s = self.make_sign_params(messages)

        d = gm.invert(e, (self._p-1)*(self._q-1))

        abc = self.calculate_abc(ms, s)
        v = pow(abc, d, self.modulus)
        return e, s, v

    def verify(self, e, s, v, messages):
        ms = [hash_message_as_int(m) for m in messages]
        abc = self.calculate_abc(ms, s)
        return pow(v, e, self.modulus) == abc

    def make_sign_params(self, messages):
        if len(messages) != len(self.a):
            raise ValueError("must have %d messages to sign, you provided %d", len(self.a), len(messages))
        ms = [hash_message_as_int(m) for m in messages]

        ln = self._n.bit_length()
        lm = ms[0].bit_length()
        le = lm+2
        ls = lm + ln + self.l

        e = gen_prime(le, secret_prime=False)
        s = secrets.randbits(ls)
        s = gm.bit_set(s, ls-1)

        return e, ms, s



