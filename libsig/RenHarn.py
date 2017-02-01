from gmpy2 import invert, gcd
from hashlib import sha256

from libsig.primes import gen_prime, is_safe_prime
from libsig.secrets import randrange


class RenHarn:
    @staticmethod
    def keygen(size=1024, g=None, p=None):
        """returns a (public, private, generator, prime)-keypair."""
        if (p is None) or (g is None):
            return ElGamal.keygen(size)
        else:
            d = randrange(2, p - 1)
            e = pow(g, d, p)
            return e, d, g, p

    @staticmethod
    def ringsign(privkey, pubkeys, message, g, p):
        """returns a signature. The privkey is the private key
        generated by keygen. pubkeys is an array of the public keys in
        the ring, including the pubkeys corresponding to privkey. The
        message is an array of bytes.
        """
        h = lambda m: int(sha256(m).hexdigest(), 16)
        k = h(message)
        message = str(message)
        v = randrange(1, p)
        messages = []
        n = len(pubkeys)
        for i in range(n):
            e_i = pubkeys[i]
            a_i = randrange(1, p - 1)
            while 1:
                b_i = randrange(1, p - 1)
                if gcd(b_i, p - 1) == 1:
                    break
            alpha_i = (pow(g, a_i, p) * pow(e_i, b_i, p)) % p
            beta_i = (- alpha_i * invert(b_i, p - 1)) % (p - 1)
            m_i = (a_i * beta_i) % (p - 1)
            messages.append((m_i, alpha_i, beta_i))
        messages[0] = (0, None, None)
        v_i_s = [None]*n
        v_i_s[1] = h(str.encode(message + str(v)))
        for i in [(x % n) for x in irange(2, n)]:
            tmp = (v_i_s[i - 1] + messages[i - 1][0]) % p
            v_i_s[i] = h(str.encode(message + str(tmp)))
        messages[0] = (v - v_i_s[0], None, None)
        while 1:
            l = randrange(2, p)
            if gcd(l, p - 1) == 1:
                break
        alpha_s = pow(g, l, p)
        beta_s = ((messages[0][0] - privkey * alpha_s) * invert(l, p - 1)) % (p - 1)
        messages[0] = (messages[0][0], alpha_s, beta_s)
        for i in range(n):
            assert pow(g, messages[i][0], p) == (pow(pubkeys[i], messages[i][1], p) * pow(messages[i][1], messages[i][2], p)) % p
        z = randrange(0, n)
        return pubkeys, z, v_i_s[z], messages

    @staticmethod
    def verify(pubkeys, i_0, v_i_0, message, ms, g, p):
        message = str(message)
        assert len(pubkeys) == len(ms)
        n = len(pubkeys)
        for i in range(n):
            if pow(g, ms[i][0], p) != (pow(pubkeys[i], ms[i][1], p) * pow(ms[i][1], ms[i][2], p)) % p:
                return False
        h = lambda m: int(sha256(m).hexdigest(), 16)
        v = h(str.encode(message + str((ms[i_0][0] + v_i_0) % p)))
        for i in range(1, n):
            v = h(str.encode(message + str((ms[(i + i_0) % n][0] + v) % p)))
        return v == v_i_0


def irange(start, stop):
    return range(start, stop + 1)


class ElGamal:
    @staticmethod
    def keygen(size=1024):
        """returns a (public, private, generator, prime)-keypair."""
        p = gen_prime(size, extra_check=is_safe_prime)
        q = p // 2
        while 1:
            g = randrange(3, p)
            if pow(g, 2, p) == 1:
                continue
            if pow(g, q, p) == 1:
                continue
            if divmod(p - 1, g)[1] == 0:
                continue
            if divmod(p - 1, invert(g, p))[1] == 0:
                continue
            break
        d = randrange(2, p - 1)
        e = pow(g, d, p)
        return e, d, g, p

    @staticmethod
    def sign(d, message, g, p):
        """returns a signature. The privkey is the private key
        generated by keygen. The message is an array of bytes.
        """
        m = int(sha256(message).hexdigest(), 16)
        l = randrange(2, p - 1)
        while gcd(l, p - 1) != 1:
            l = randrange(2, p - 1)
        alpha = pow(g, l, p)
        beta = ((m - d * alpha) * invert(l, p - 1)) % (p - 1)
        return alpha, beta

    @staticmethod
    def verify(e, message, signature, g, p):
        """returns True iff the signature is correct."""
        alpha, beta = signature
        if alpha < 1 or alpha >= p:
            return False
        m = int(sha256(message).hexdigest(), 16)
        return pow(g, m, p) == (pow(e, alpha, p) * pow(alpha, beta, p)) % p
