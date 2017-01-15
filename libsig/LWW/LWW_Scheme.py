import hashlib



q #Primzahl
n #Anzahl User

def H1(x):
    y = hashlib.sha512(x)
    z = y mod q
    return z

def H2(x):
    y = hashlib.sha3_512(x)
    z = ?
    return z
