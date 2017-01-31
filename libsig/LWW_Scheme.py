import hashlib
import sys
from random import randint
from libsig.primes import *
from libsig.AbstractRingSignatureScheme import AbstractRingSignatureScheme


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
        y = int(hashlib.sha512(x).hexdigest(), 16)
        z = y % q
        return z

    @staticmethod
    def __verifyQandG(pubKeys):
        """
        Verifies that all pubKeys have the same q and g and returns them
        :param pubKeys: List of Public Keys with q and g (y, q, g)
        :return: (q,g) if all are the same
        """
        q = pubKeys[0][1]
        g = pubKeys[0][2]
        for completePubKey in pubKeys:
            if q != completePubKey[1]:
                raise ValueError("A q is not equal to the others, check your keys")
            if g != completePubKey[2]:
                raise ValueError("A g is not equal to the others, check your keys")

        return q, g

    @staticmethod
    def __checkWhichUser(privUser, pubKeys):
        """
        Methode bekommt einen priv. Key und eine Liste von public Keys (y,q,g) und gibt dann die Position des eigenen public keys zurueck
        :param pubKeys:
        :return:
        """
        userIndex = 0
        q = pubKeys[0][1]
        g = pubKeys[0][2]
        tmp = pow(g, privUser, q)
        for i in range(len(pubKeys)):
            if tmp == pubKeys[i][0]:
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
            g = randint(1, q)

        x = randint(1, q - 1)
        y = pow(g, x, q)
        return [y, x, q, g]

    # sign-Methode fuer Ringsignatur
    @staticmethod
    def ringsign(privKeyUser, pubKeys, message):
        q, g = LWW.__verifyQandG(pubKeys)
        # Check which user we are
        userIndex = LWW.__checkWhichUser(privKeyUser, pubKeys)

        # Part 1
        h = LWW.h2(str(pubKeys).encode(), q)
        ytilde = pow(h, privKeyUser, q)

        # Part 2
        # Hier werden alle benoetigten Teile zu einer Liste zusammengefuegt, die dann gehashed unser neues c ergeben
        u = randint(1, q - 1)
        K = pubKeys
        K.append(ytilde)
        K.append(message)
        K.append(pow(g, u, q))
        K.append(pow(h, u, q))
        c = LWW.h1(str(K).encode(), q)

        # Part 3
        # hier wird c immer mit dem neuen c-Wert ueberschrieben, da der vorherige nicht mehr benoetigt wird
        c1 = 0
        s = range(len(pubKeys))
        for i in range(1, len(pubKeys)):
            j = (i + userIndex) % len(pubKeys)
            if j == 1:
                c1 = c
            si = randint(1, q - 1)
            s[j - 1] = si

            # Hier werden wieder alle benoetigten Teile zu einer Liste zusammengefuegt, die dann gehashed unser neues c ergeben
            K = pubKeys
            K.append(ytilde)
            K.append(message)
            K.append(pow(g, si, q) * pow(pubKeys[j], c, q))
            K.append(pow(h, si, q) * pow(ytilde, c, q))
            c = LWW.h1(str(K).encode(), q)

            # Part 4
        s[userIndex - 1] = (u - c * privKeyUser) % q

        # Finish
        sig = []
        sig.append(c1)
        sig.append(s)
        sig.append(ytilde)

        return sig

    # Methode zum Pruefen, ob eine signatur bei gegebenen public Keys korrekt erzeugt wurde
    @staticmethod
    def verify(pubKeys, message, signature):
        q, g = LWW.__verifyQandG(pubKeys)

        # Part 1
        c = signature[0]
        h = LWW.h2(str(pubKeys).encode(), q)

        for i in range(1, len(pubKeys) + 1):
            z1 = pow(g, signature[i], q) * pow(pubKeys[i - 1], c, q)
            z2 = pow(h, signature[i], q) * pow(signature[len(signature) - 1], c, q)

            # Hier werden wieder alle benoetigten Teile zu einer Liste zusammengefuegt, die dann gehashed unser neues c ergeben
            K = pubKeys
            K.append(signature[len(signature) - 1])
            K.append(message)
            K.append(z1)
            K.append(z2)
            c = LWW.h1(str(K).encode(), q)

        # Part 2
        if signature[0] == c:
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
    listKeys = []
    for i in range(n):
        b = LWW.keygen(13, 2)
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
    print(publicKeys)
    print(privateKey)
    print(userIndex)

    message = "Hallo"
    # sign-Test
    testsig = LWW.ringsign(privateKey, publicKeys, message)
    print(testsig)

    # Verify-Test
    check = LWW.verify(publicKeys, message, testsig)
    print(check)


if __name__ == "__main__":
    sys.exit(main())
