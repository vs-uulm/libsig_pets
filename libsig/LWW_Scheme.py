import hashlib
from random import randint
from libsig.primes import *
from libsig.AbstractRingSignatureScheme import AbstractRingSignatureScheme


class LWW(AbstractRingSignatureScheme):
    """
    Implementation of a RingSign Algorithm
    Name: "Linkable Spontaneous Anonymous Group Signature for Ad Hoc Groups"
    From: Joseph K. Liu, Victor K. Wei, and Duncan S. Wong
    By: Jan Klumpp, Nicola Fröhlich, Wolf Michael
    """

    @staticmethod
    def h1(x, q):
        """
        Hash Function 1 where {0,1}* -> Zq
        Uses Sha512
        :param q: Order of group G
        :param x: Value to Hash
        :return: Hashed Value with modulo q
        """
        if q is None or q == 0:
            raise ValueError("Please provide the Argument q.")
        y = int(hashlib.sha512(x).hexdigest(), 16)
        z = y % q
        return z

    @staticmethod
    def h2(x, q):
        """
        Hash Function 2 where {0,1}* -> G and statistically independent of H1
        Uses Sha256
        :param q: Order of group G
        :param x: Value to Hash
        :return: Hashed Value with modulo q
        """
        if q is None or q == 0:
            raise ValueError("Please provide the Argument q.")
        y = int(hashlib.sha256(x).hexdigest(), 16)
        z = y % q
        return z

    @staticmethod
    def __verifyQandG(completePublicKeys):
        """
        Verifies that all publicKeys have the same q and g and returns them
        :param completePublicKeys: List of Public Keys with q and g (y, q, g)
        :return: (publicKeys,q,g) if all q and g are the same, else a error is raised.
                publicKeys = only public keys without q and g
        """
        q = completePublicKeys[0][1]
        g = completePublicKeys[0][2]
        publicKeys = []
        for completePubKey in completePublicKeys:
            if q != completePubKey[1]:
                raise ValueError("A q is not equal to the others, check your keys")
            if g != completePubKey[2]:
                raise ValueError("A g is not equal to the others, check your keys")
            publicKeys.append(completePubKey[0])

        return publicKeys, q, g

    # ------ Begin Implementation of AbstractRingSignatureScheme -----

    @staticmethod
    def keygen(q=0, g=0):
        """
        Creates Private and Public key of optional given q and g
        If no arguments are given, default values will be used
        :param q: Order of group G
        :param g: Generator of Group G with the prime order q
        :return: [y=public, x=private, q=Order, g=Generator]
        """
        if q == 0:
            q = safe_prime_1024_1
        if g == 0:
            g = 123456

        x = randint(1, q - 1)
        y = pow(g, x, q)
        return [y, x, q, g]

    @staticmethod
    def ringsign(privateKeyUser, completePublicKeys, message):
        """
        Signs the message with the given privateKey of the user and the public keys
        Is using the algorithm of "Linkable Spontaneous Anonymous Group Signature for Ad Hoc Groups"
        :param privateKeyUser: The private Key of the User
        :param completePublicKeys:  A List of Public Keys with the form [y=public, x=private, q=Order, g=Generator]
        :param message: Just a random message
        :return: The signature in the form of [C1, [S1, ..., Sn], y~]
        """
        publicKeys, q, g = LWW.__verifyQandG(completePublicKeys)
        publicKeysLength = len(publicKeys)
        userIndex = publicKeys.index(pow(g, privateKeyUser, q))

        # Part 1
        h = LWW.h2(repr(publicKeys).encode(), q)
        y_Tilde = pow(h, privateKeyUser, q)

        # Part 2
        u = randint(1, q - 1)
        K = [publicKeys, y_Tilde, message, pow(g, u, q), pow(h, u, q)]

        # Part 3
        s = [-1] * publicKeysLength
        c = [-1] * publicKeysLength
        i = (userIndex + 1) % publicKeysLength
        c[i] = LWW.h1(repr(K).encode(), q)
        while i != userIndex:
            si = randint(1, q - 1)
            s[i] = si

            z1 = (pow(g, si, q) * pow(publicKeys[i], c[i], q)) % q
            z2 = (pow(h, si, q) * pow(y_Tilde, c[i], q)) % q
            K = [publicKeys, y_Tilde, message, z1, z2]
            i = (i + 1) % publicKeysLength
            c[i] = LWW.h1(repr(K).encode(), q)

        # Part 4
        s[userIndex] = (u - privateKeyUser * c[userIndex]) % (q-1)

        # Finish
        sig = [c[0], s, y_Tilde]

        return sig

    @staticmethod
    def verify(completePublicKeys, message, signature):
        """
        Verifies that the given message is signed by one of the public key users
        :param completePublicKeys:  A List of Public Keys with the form [y=public, q=Order, g=Generator]
        :param message: Just a random message
        :param signature: The signature in the form of [C1, [S1, ..., Sn], y~]
        :return: 'True' if accepted, 'False' if not
        """
        publicKeys, q, g = LWW.__verifyQandG(completePublicKeys)
        publicKeysLength = len(publicKeys)

        c1 = signature[0]
        singleSignatures = signature[1]
        y_Tilde = signature[2]

        if publicKeysLength != len(signature[1]):
            raise ValueError("The length of the public Keys does not match to the length of signatures/ secrets")

        # Part 1
        c_i = c1
        h = LWW.h2(repr(publicKeys).encode(), q)

        for i in range(0, publicKeysLength):
            z1 = (pow(g, singleSignatures[i], q) * pow(publicKeys[i], c_i, q)) % q
            z2 = (pow(h, singleSignatures[i], q) * pow(y_Tilde, c_i, q)) % q
            K = [publicKeys, y_Tilde, message, z1, z2]
            c_i = LWW.h1(repr(K).encode(), q)

        # Part 2
        if c1 == c_i:
            return True
        else:
            return False

    # ------ End Implementation of AbstractRingSignatureScheme -----
