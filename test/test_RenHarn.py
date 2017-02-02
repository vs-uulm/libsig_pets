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
        (self.pubkey, self.privkey) = ElGamal.keygen(keysize)

    def test_sign_and_verify(self):
        """
        Test if we can verify a signed message.
        """
        message = str.encode("Star wars is awesome")
        signature = ElGamal.sign(self.privkey, message)
        self.assertTrue(ElGamal.verify(self.pubkey, message, signature))


class TestRenHarn(unittest.TestCase):
    """We inherit from unittest.TestCase, so that nosetest can
    automatically detect the tests.
    You can think of this as 'JUnit for Python'.
    """
    def setUp(self, keysize=512):
        """This is a special function which is called before each of
        our tests."""
        # We set up the keys and params
        (e, d) = RenHarn.keygen(keysize)
        self.privkeys = [d]
        self.pubkeys = [e]
        for _ in range(15):
            (e, d) = RenHarn.keygen(keysize, self.pubkeys[0][1], self.pubkeys[0][2])
            self.privkeys.append(d)
            self.pubkeys.append(e)

    def test_ring_sign_and_verify(self):
        """
        Test if we can verify a signed message.
        """
        n = len(self.pubkeys)

        message = str.encode("Star wars is awesome")
        sig = RenHarn.ringsign(self.privkeys[0], self.pubkeys, message)
        self.assertTrue(RenHarn.verify(self.pubkeys, message, sig))

    def test_wrong_idx(self):
        n = len(self.pubkeys)
        message = str.encode("Star wars is awesome")
        (i_0, v_i_0, ms) = RenHarn.ringsign(self.privkeys[0], self.pubkeys, message)
        for i in range(n-1):
            sig = ((i_0+i+1) % n, v_i_0, ms)
            self.assertFalse(RenHarn.verify(self.pubkeys, message, sig))

    def test_wrong_pubkey(self):
        n = len(self.pubkeys)
        message = str.encode("Star wars is awesome")
        sig = RenHarn.ringsign(self.privkeys[0], self.pubkeys, message)
        pk = self.pubkeys
        pk[n-1] = (12345678765432943458754347854345689843456723974982891365294562364 % self.pubkeys[0][2], pk[n-1][1], pk[n-1][2])
        self.assertFalse(RenHarn.verify(pk, message, sig))

    def test_wrong_signature(self):
        pubkeys = self.pubkeys
        n = len(pubkeys)
        m = str.encode("Star wars is awesome")
        sig = RenHarn.ringsign(self.privkeys[0], pubkeys, m)
        for i in range(n):
            for magic_number in [-1, 0, 1]:
                (m, alpha, beta) = sig[2][i]
                sig[2][i] = ((m + magic_number) % n, alpha, beta)
                self.assertFalse(RenHarn.verify(pubkeys, m, sig))
                sig[2][i] = (m, (alpha + magic_number) % n, beta)
                self.assertFalse(RenHarn.verify(pubkeys, m, sig))
                sig[2][i] = (m, alpha, (beta + magic_number) % n)
                self.assertFalse(RenHarn.verify(pubkeys, m, sig))
                sig[2][i] = (magic_number % n, alpha, beta)
                self.assertFalse(RenHarn.verify(pubkeys, m, sig))
                sig[2][i] = (m, magic_number % n, beta)
                self.assertFalse(RenHarn.verify(pubkeys, m, sig))
                sig[2][i] = (m, alpha, magic_number % n)
                self.assertFalse(RenHarn.verify(pubkeys, m, sig))
                sig[2][i] = (m, alpha, beta)


if __name__ == 'main':
    unittest.main()
