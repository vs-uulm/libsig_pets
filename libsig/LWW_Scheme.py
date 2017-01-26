import hashlib
import sys
import gmpy2
from random import randint
from libsig.primes import *
from libsig.AbstractRingSignatureScheme import AbstractRingSignatureScheme


class LWW(AbstractRingSignatureScheme):
    """Some Docu"""
    def __init(self, q):
        self._q = q
        self._g = randint(q/2, q-1) # Generator der Gruppe G zur Primzahl q. Da q Prim gilt dass jedes g mit 0<g<q ein Generator

    @property
    def q(self):
        """Order of group G"""
        return self._q

    @property
    def g(self):
        """Generator of Group G with the prime order q"""
        return self._g


    def h1(self, x):
        """
        Hash Funktion 1
        bekommt einen x-Wert und berechnet einen Sha2-512 Bit Wert daraus (im Modul zu q)
        :param x:
        :return:
        """
        y = int(hashlib.sha512(x).hexdigest(), 16)
        z = y % self.q
        return z



    def h2(self, x):
        """
        Hash-Funktion 2
        bekommt einen x-Wert und berechnet einen Sha3-512 Bit Wert daraus (im Modul zu q)
        laut Henning ist der dann automatisch in G
        :param x:
        :return:
        """
        y = int(hashlib.sha3_512(x).hexdigest(), 16)
        z = y % self.q
        return z


    def generatorDummie(self):
        """
        eine unserer Test-Methoden
        erstellt mal eine Liste mit public Keys und gibt uns einen (zufällig ausgewählten) zugehörigen privat key als eigenen privat-Key zurück
        :return:
        """
        listKeys = []
        for i in range(self.n):
            b = self.keygen()
        listKeys.append(b)

        userIndexi = randint(1, self.n)
        useri = listKeys[userIndexi - 1]

        keys = []
        for i in range(len(listKeys)):
            keys.append(listKeys[i][0])

        return [keys, useri[1]]


    def _checkWhichUser(self, privUser, L):
        """
        Methode bekommt einen priv. Key und eine Liste von public Keys und gibt dann die Position des eigenen public keys zurück
        :param L:
        :return:
        """
        # list.index(tmp)
        tmp = pow(self.g, privUser, self.q)
        for i in range(len(L)):
            if tmp == L[i]:
                userIndex = i + 1
                break
        return userIndex

    # ------ Anfang -----
    def keygen(self):
        x = randint(1, self.q - 1)
        y = pow(self.g, x, self.q)
        return [y, x]

    # Sign-Methode für Ringsignatur
    def ringsign(self, privKeyUser, pubkeys, message):
        # Check which user we are
        userIndex = checkWhichUser(privKeyUser, pubkeys)

        # Part 1
        h = h2(str(pubkeys).encode())
        ytilde = pow(h, privKeyUser, q)

        # Part 2
        # Hier werden alle benötigten Teile zu einer Liste zusammengefügt, die dann gehashed unser neues c ergeben
        u = randint(1, q - 1)
        K = pubkeys
        K.append(ytilde)
        K.append(message)
        K.append(pow(g, u, q))
        K.append(pow(h, u, q))
        c = H1(str(K).encode())

        # Part 3
        # hier wird c immer mit dem neuen c-Wert überschrieben, da der vorherige nicht mehr benötigt wird
        c1 = 0
        s = range(len(pubkeys))
        for i in range(1, len(pubkeys)):
            j = (i + userIndex) % len(pubkeys)
            if j == 1:
                c1 = c
            si = randint(1, q - 1)
            s[j - 1] = si

            # Hier werden wieder alle benötigten Teile zu einer Liste zusammengefügt, die dann gehashed unser neues c ergeben
            K = pubkeys
            K.append(ytilde)
            K.append(message)
            K.append(pow(g, si, q) * pow(pubkeys[j], c, q))
            K.append(pow(h, si, q) * pow(ytilde, c, q))
            c = H1(str(K).encode())

            # Part 4
        s[userIndex - 1] = (u - c * privKeyUser) % q

        # Finish
        Sig = []
        Sig.append(c1)
        Sig.append(s)
        Sig.append(ytilde)

        return Sig


    # Methode zum Prüfen, ob eine Signatur bei gegebenen public Keys korrekt erzeugt wurde
    def verify(pubkeys, message, signature):
        # Part 1
        c = signature[0]
        h = H2(str(pubkeys).encode())
        z1 = 0
        z2 = 0
        K = []
        for i in range(1, len(pubkeys) + 1):
            z1 = pow(g, signature[i], q) * pow(pubkeys[i - 1], c, q)
            z2 = pow(h, signature[i], q) * pow(signature[len(signature) - 1], c, q)

            # Hier werden wieder alle benötigten Teile zu einer Liste zusammengefügt, die dann gehashed unser neues c ergeben
            K = pubkeys
            K.append(signature[len(signature) - 1])
            K.append(message)
            K.append(z1)
            K.append(z2)
            c = H1(str(K).encode())

        # Part 2
        if signature[0] == c:
            return True
        else:
            return False



# main-Methode, damit wir mal alles testen können
def main():
    # Beispielswerte für g und n
    g = randint(1, q - 1)  # ist q Prim, so ist jede Zahl 0<g<q ein Generator
    n = 10

    # Erzeugt mal einige Keys zum Test
    keys = generatorDummie()
    print(keys)
    L = keys[0]
    privKeyUser = keys[1]
    message = "Hallo"
    # Check which user we are
    userIndex = checkWhichUser(privKeyUser, keys)
    print(userIndex)

    # Sign-Test
    testsig = ringsign(privKeyUser, L, message)
    print(testsig)

    # Verify-Test
    check = verify(L, message, testsig)
    print(check)


if __name__ == "__main__":
    sys.exit(main())
