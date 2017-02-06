import sys
import hashlib
if sys.version_info < (3, 6):
    import sha3
from random import randint
from libsig.primes import *
from libsig.AbstractRingSignatureScheme import AbstractRingSignatureScheme


# noinspection PyPep8Naming
class LWW(AbstractRingSignatureScheme):
    """Some Docu"""

    @staticmethod
    def h1(x, q):
        """
        Hash Funktion 1
        bekommt einen x-Wert und berechnet einen Sha2-512 Bit Wert daraus (im Modul zu q)
        :param q:
        :param x:
        :return:
        """
        y = int(hashlib.sha512(x).hexdigest(), 16)
        z = y % q
        return z

    @staticmethod
    def h2(x, q):
        """
        Hash-Funktion 2
        bekommt einen x-Wert und berechnet einen Sha3-512 Bit Wert daraus (im Modul zu q)
        laut Henning ist der dann automatisch in G
        :param q:
        :param x:
        :return:
        """
        y = int(hashlib.sha3_512(x).hexdigest(), 16)
        z = y % q
        return z

    @staticmethod
    def __verifyQandG(completepublicKeys):
        """
        Verifies that all publicKeys have the same q and g and returns them
        :param completepublicKeys: List of Public Keys with q and g (y, q, g)
        :return: (publicKeys,q,g) if all q and g are the same, else a error is raised. publicKeys = only public keys without q and g
        """
        q = completepublicKeys[0][1]
        g = completepublicKeys[0][2]
        publicKeys = []
        for completePubKey in completepublicKeys:
            if q != completePubKey[1]:
                raise ValueError("A q is not equal to the others, check your keys")
            if g != completePubKey[2]:
                raise ValueError("A g is not equal to the others, check your keys")
            publicKeys.append(completePubKey[0])

        return publicKeys, q, g

    @staticmethod
    def __checkWhichUser(privateKeyUser, publicKeys, q, g):
        """
        Methode bekommt einen priv. Key und eine Liste von public Keys  und gibt dann die Position des eigenen public keys zurueck
        :param publicKeys:
        :return:
        """
        userIndex = 0
        tmp = pow(g, privateKeyUser, q)
        for i in range(len(publicKeys)):
            if tmp == publicKeys[i]:
                userIndex = i
                break
        return userIndex

    # ------ Anfang -----
    @staticmethod
    def keygen(q=0, g=0):
        """
        Creates Private and Public key of optional given q and g
        :param q: Order of group G
        :param g: Generator of Group G with the prime order q
        :return: [y=public, x=private, q=Order, g=Generator]
        """
        if q == 0:
            q = safe_prime_1024_1
        if g == 0:
            g = randint(2, q - 1)

        x = randint(1, q - 1)
        y = pow(g, x, q)
        return [y, x, q, g]

    # sign-Methode fuer Ringsignatur
    @staticmethod
    def ringsign(privateKeyUser, completePublicKeys, message):
        print("----- Sign -----")
        publicKeys, q, g = LWW.__verifyQandG(completePublicKeys)
        publicKeysLength = len(publicKeys)
        # Check which user we are
        userIndex = LWW.__checkWhichUser(privateKeyUser, publicKeys, q, g)

        # Part 1
        h = LWW.h2(str(publicKeys).encode(), q)
        print("H = " + str(h))
        ytilde = pow(h, privateKeyUser, q)
        print("YTilde = " + str(ytilde))
        # Part 2
        # Hier werden alle benoetigten Teile zu einer Liste zusammengefuegt, die dann gehashed unser neues c ergeben
        u = randint(1, q - 1)
        print("U = " + str(u))
        K = [publicKeys, ytilde, message, pow(g, u, q), pow(h, u, q)]
        print("K:" + str(K))
        print(str(K).encode())
        print(''.join('{:02x}'.format(x) for x in str(K).encode()))
        ci = LWW.h1(str(K).encode(), q)
        c1 = ci

        # Part 3
        # hier wird c immer mit dem neuen c-Wert ueberschrieben, da der vorherige nicht mehr benoetigt wird
        #c1 = 0
        s = [None] * publicKeysLength
        c = [None] * publicKeysLength
        for j in range(1, publicKeysLength):
            i = (j + userIndex) % publicKeysLength

            si = randint(1, q - 1)
            s[i] = si

            z1 = (pow(g, si, q) * pow(publicKeys[i], ci, q)) % q
            z2 = (pow(h, si, q) * pow(ytilde, ci, q)) % q

            # Hier werden wieder alle benoetigten Teile zu einer Liste zusammengefuegt, die dann gehashed unser neues c ergeben
            K = [publicKeys, ytilde, message, z1, z2]
            print("K:" + str(K))

            ci = LWW.h1(str(K).encode(), q)
            if i == 0:
                c1 = ci #To Save c1 (Index 0)

            print(str(i) + ": s=" + str(si) + " - c= " + str(ci))

        # Part 4
        s[userIndex] = (u - privateKeyUser * ci) % q
        print(str(userIndex) + ": s=" + str(s[userIndex]) + " - c= " + str(ci))

        # Finish
        sig = [c1, s, ytilde]

        return sig

    # Methode zum Pruefen, ob eine signatur bei gegebenen public Keys korrekt erzeugt wurde
    @staticmethod
    def verify(completePublicKeys, message, signature):
        print("----- Verify -----")

        publicKeys, q, g = LWW.__verifyQandG(completePublicKeys)
        publicKeysLength = len(publicKeys)

        c1 = signature[0]
        singleSignatures = signature[1]
        ytilde = signature[2]

        if publicKeysLength != len(signature[1]):
            raise ValueError("The length of the public Keys does not match to the length of signatures/ secrets")

        print(str(publicKeys).encode())
        # Part 1
        c = c1
        h = LWW.h2(str(publicKeys).encode(), q)

        for j in range(0, publicKeysLength):
            i = (j+1) % publicKeysLength
            z1 = (pow(g, singleSignatures[i], q) * pow(publicKeys[i], c, q)) % q
            z2 = (pow(h, singleSignatures[i], q) * pow(ytilde, c, q)) % q
            print("Z1: " + str(g) + "^" + str(singleSignatures[i]) + " * " + str(publicKeys[i]) + "^" + str(c))
            print("Z2: " + str(h) + "^" + str(singleSignatures[i]) + " * " + str(ytilde) + "^" + str(c))
            # Hier werden wieder alle benoetigten Teile zu einer Liste zusammengefuegt, die dann gehashed unser neues c ergeben
            K = [publicKeys, ytilde, message, z1, z2]
            print("K:" + str(K))

            c = LWW.h1(str(K).encode(), q)
            print(str(i) + ": s=" + str(singleSignatures[i]) + " - c= " + str(c))

        # Part 2
        if c1 == c:
            return True
        else:
            return False


def generatorDummie(n):
    """
    eine unserer Test-Methoden
    erstellt mal eine Liste mit public Keys und gibt uns einen (zufaellig ausgewaehlten) zugehoerigen privat key als eigenen privat-Key zurueck
    :param n: Number of Users n
    :return:
    """
    # return [(12, 13, 2), (2, 13, 2)], 1, 1
    listKeys = []
    for i in range(n):
        b = LWW.keygen(13, 8)
        listKeys.append(b)

    keys = []
    for i in range(len(listKeys)):
        keys.append((listKeys[i][0], listKeys[i][2], listKeys[i][3]))

    userIndex = randint(0, n - 1)
    user = listKeys[userIndex]

    return keys, user[1], userIndex


# main-Methode, damit wir mal alles testen koennen
def main():
    # Erzeugt mal einige Keys zum Test
    publicKeys, privateKey, userIndex = generatorDummie(4)
    print("CompletePublicKeys= " + str(publicKeys))
    print("PrivateKeyUser= " + str(privateKey))
    print("UserIndex= " + str(userIndex))

    message = "Hallo"
    print("Message= " + str(message))
    # sign-Test
    testsig = LWW.ringsign(privateKey, publicKeys, message)
    print("TestSig=" + str(testsig))

    # Verify-Test
    check = LWW.verify(publicKeys, message, testsig)
    print("VerifyResult= " + str(check))


if __name__ == "__main__":
    sys.exit(main())

