import unittest
from libsig.LWW_Scheme import LWW
from libsig.primes import safe_prime_1024_1


class TestLWW(unittest.TestCase):
    """
    UnitTests for the Module LWW_Scheme/ Class LWW.
    """

    def test_keygen_NoArguments_UseDefaultValues(self):
        publicKey, privateKey, default_q, default_g = LWW.keygen()

        self.assertEqual(default_q, safe_prime_1024_1)
        self.assertEqual(default_g, 123456)

    def test_keygen_GetCorrectlyCalculatedPublicKey(self):
        publicKey, privateKey, q, g = LWW.keygen(13, 2)

        self.assertTrue(privateKey < q-1)
        self.assertEqual(publicKey, pow(g, privateKey, q))

    def test_sign_and_verify_WithStartingPosition(self):
        """
        Test if we can verify a signed message, where the User is in the starting position 0.
        """
        publicKeys, privateKey = self.generatorDummy(5, 0)
        message = str.encode("You can't stump the Trump!")

        signature = LWW.ringsign(privateKey, publicKeys, message)

        self.assertTrue(LWW.verify(publicKeys, message, signature), True)

    def test_sign_and_verify_WithMiddlePosition(self):
        """
        Test if we can verify a signed message, where the User is in the middle position 2.
        """
        publicKeys, privateKey = self.generatorDummy(5, 2)
        message = str.encode("You can't stump the Trump!")

        signature = LWW.ringsign(privateKey, publicKeys, message)

        self.assertTrue(LWW.verify(publicKeys, message, signature), True)

    def test_sign_and_verify_WithEndingPosition(self):
        """
        Test if we can verify a signed message, where the User is in the ending position 4.
        """
        publicKeys, privateKey = self.generatorDummy(5, 4)
        message = str.encode("You can't stump the Trump!")

        signature = LWW.ringsign(privateKey, publicKeys, message)

        self.assertTrue(LWW.verify(publicKeys, message, signature), True)

    @staticmethod
    def generatorDummy(n, userIndex):
        """
        Method to Generate a Dummy pair
        :param n: Number of Users n
        :param userIndex: Set the Position of the User (privatekey), starting with 0
        :return: PublicKeys (y, q, g), PrivateKeyUser
        """
        completeKeys = []
        for i in range(n):
            b = LWW.keygen(13, 2)
            completeKeys.append(b)

        publicKeys = []
        for i in range(len(completeKeys)):
            publicKeys.append((completeKeys[i][0], completeKeys[i][2], completeKeys[i][3]))

        user = completeKeys[userIndex]

        return publicKeys, user[1]


if __name__ == 'main':
    unittest.main()
