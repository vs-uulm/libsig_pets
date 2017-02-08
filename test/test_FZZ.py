"""This file contains unittests for the FZZ Unique Ring Signature."""

import unittest
#from libsig.FZZ_unique_ring_signature import UniqueRingSignature
from FZZ_unique_ring_signature import UniqueRingSignature

class TestUniqueRingSignature(unittest.TestCase):
    """We inherit from unittest.TestCase, so that nosetest can
    automatically detect the tests.
    You can think of this as 'JUnit for Python'.
    """
    def setUp(self):
        """This is a special function which is called before each of
        our tests."""
        # We set up the keys and params
        self.ring = list()
        self.privkey, self.pubkey = UniqueRingSignature.keygen()
        self.ring.append(self.pubkey)

    def test_sign_and_verify(self):
        """
        Test if we can verify a signed message.
        """
        message = "Star wars is awesome"
        signature = UniqueRingSignature.ringsign(self.privkey, self.ring, message)
        self.assertTrue(UniqueRingSignature.verify(self.ring, message, signature))

    def test_multi_user_sign(self):
        """
        Check that rign signature works for more than one user.
        """
        ring = list()
        user1_priv, user1_pub = UniqueRingSignature.keygen()
        ring.append(user1_pub)

        user2_priv, user2_pub = UniqueRingSignature.keygen()
        ring.append(user2_pub)

        user3_priv, user3_pub = UniqueRingSignature.keygen()
        ring.append(user3_pub)

        message = "Star wars is awesome"
        signature = UniqueRingSignature.ringsign(user2_priv, ring, message)
        self.assertTrue(UniqueRingSignature.verify(ring, message, signature))

    def test_multi_sign_and_replaced_one(self):
        """
        Check that rign signature works for more than one user.
        """
        ring = list()
        ring2 = list()
        user1_priv, user1_pub = UniqueRingSignature.keygen()
        ring.append(user1_pub)
        ring2.append(user1_pub)

        user2_priv, user2_pub = UniqueRingSignature.keygen()
        ring.append(user2_pub)
        ring2.append(user2_pub)

        user3_priv, user3_pub = UniqueRingSignature.keygen()
        ring.append(user3_pub)

        user4_priv, user4_pub = UniqueRingSignature.keygen()
        ring2.append(user4_pub)

        message = "Star wars is awesome"
        signature = UniqueRingSignature.ringsign(user2_priv, ring, message)
        self.assertFalse(UniqueRingSignature.verify(ring2, message, signature))



if __name__ == '__main__':
    unittest.main()
