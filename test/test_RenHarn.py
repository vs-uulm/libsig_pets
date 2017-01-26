"""This file contains unittests for the ElGamal and RenHarn signature schemes."""

import unittest
from libsig.RenHarn import ElGamal, RenHarn


class TestElGamal(unittest.TestCase):
    """We inherit from unittest.TestCase, so that nosetest can
    automatically detect the tests.
    You can think of this as 'JUnit for Python'.
    """
    def setUp(self, keysize=512):
        """This is a special function which is called before each of
        our tests."""
        # We set up the keys and params
        (self.pubkey, self.privkey, self.generator, self.prime) = ElGamal.keygen(keysize)

    def test_sign_and_verify(self):
        """
        Test if we can verify a signed message.
        """
        message = str.encode("Star wars is awesome")
        signature = ElGamal.sign(self.privkey, message, self.generator, self.prime)
        self.assertTrue(ElGamal.verify(self.pubkey, message, signature, self.generator, self.prime))


class TestRenHarn(unittest.TestCase):
    """We inherit from unittest.TestCase, so that nosetest can
    automatically detect the tests.
    You can think of this as 'JUnit for Python'.
    """
    def setUp(self, keysize=512):
        """This is a special function which is called before each of
        our tests."""
        # We set up the keys and params
        (e, d, self.generator, self.prime) = RenHarn.keygen(keysize)
        self.privkeys = [d]
        self.pubkeys = [e]
        for _ in range(15):
            (e, d, _, _) = RenHarn.keygen(keysize, self.generator, self.prime)
            self.privkeys.append(d)
            self.pubkeys.append(e)

    def test_ring_sign_and_verify(self):
        """
        Test if we can verify a signed message.
        """
        n = len(self.pubkeys)

        message = str.encode("Star wars is awesome")
        (_, i_0, v_i_0, sig) = RenHarn.ringsign(self.privkeys[0], self.pubkeys, message, self.generator, self.prime)
        self.assertTrue(RenHarn.verify(self.pubkeys, i_0, v_i_0, message, sig, self.generator, self.prime))

    def test_wrong_idx(self):
        n = len(self.pubkeys)
        message = str.encode("Star wars is awesome")
        (_, i_0, v_i_0, sig) = RenHarn.ringsign(self.privkeys[0], self.pubkeys, message, self.generator, self.prime)
        for i in range(n-1):
            self.assertFalse(RenHarn.verify(self.pubkeys, (i_0+i+1) % n, v_i_0, message, sig, self.generator, self.prime))

    def test_wrong_pubkey(self):
        n = len(self.pubkeys)
        message = str.encode("Star wars is awesome")
        (_, i_0, v_i_0, sig) = RenHarn.ringsign(self.privkeys[0], self.pubkeys, message, self.generator, self.prime)
        pk = self.pubkeys
        pk[n-1] = 12345678765432943458754347854345689843456723974982891365294562364 % self.prime
        self.assertFalse(RenHarn.verify(pk, i_0, v_i_0, message, sig, self.generator, self.prime))

    def test_wrong_signature(self):
        pubkeys = self.pubkeys
        n = len(pubkeys)
        m = str.encode("Star wars is awesome")
        g = self.generator
        p = self.prime
        (_, i_0, v_i_0, sig) = RenHarn.ringsign(self.privkeys[0], pubkeys, m, g, p)
        for i in range(n):
            for magic_number in [-1, 0, 1]:
                (m, alpha, beta) = sig[i]
                sig[i] = ((m + magic_number) % n, alpha, beta)
                self.assertFalse(RenHarn.verify(pubkeys, i_0, v_i_0, m, sig, g, p))
                sig[i] = (m, (alpha + magic_number) % n, beta)
                self.assertFalse(RenHarn.verify(pubkeys, i_0, v_i_0, m, sig, g, p))
                sig[i] = (m, alpha, (beta + magic_number) % n)
                self.assertFalse(RenHarn.verify(pubkeys, i_0, v_i_0, m, sig, g, p))
                sig[i] = (magic_number % n, alpha, beta)
                self.assertFalse(RenHarn.verify(pubkeys, i_0, v_i_0, m, sig, g, p))
                sig[i] = (m, magic_number % n, beta)
                self.assertFalse(RenHarn.verify(pubkeys, i_0, v_i_0, m, sig, g, p))
                sig[i] = (m, alpha, magic_number % n)
                self.assertFalse(RenHarn.verify(pubkeys, i_0, v_i_0, m, sig, g, p))
                sig[i] = (m, alpha, beta)


if __name__ == 'main':
    unittest.main()
