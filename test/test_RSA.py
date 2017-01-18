"""This file contains unittests for the RSAsig."""

import unittest
from libsig.RSAsig import RSAsig

class TestRSAsig(unittest.TestCase):
    """We inherit from unittest.TestCase, so that nosetest can
    automatically detect the tests.
    You can think of this as 'JUnit for Python'.
    """
    def setUp(self):
        """This is a special function which is called before each of
        our tests."""
        # We set up the keys and params
        (self.pubkey, self.privkey, self.primes) = RSAsig.keygen()

    def test_sign_and_verify(self):
        """
        Test if we can verify a signed message.
        """
        message = str.encode("Star wars is awesome")
        signature = RSAsig.sign(self.privkey, message)
        self.assertTrue(RSAsig.verify(self.pubkey, message, signature), True)

    def test_no_homo(self):
        """
        Check that our RSA scheme is not homomorphic.
        """
        msg1=10
        msg2=2
        sig1 = RSAsig.sign(self.privkey, chr(msg1).encode())
        sig2 = RSAsig.sign(self.privkey, chr(msg2).encode())
        self.assertNotEqual(msg1*msg2, sig1*sig2)

if __name__ == 'main':
    unittest.main()
