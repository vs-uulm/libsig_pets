import sys
import math
from random import randint
import hashlib
from libsig.AbstractRingSignatureScheme import AbstractRingSignatureScheme
from libsig import primes


# ----------- HELPER FUNCTIONS ----------- 

# function to find divisors in order to find generators
def find_divisors(x):
    divisors = []
    for i in range(1, x + 1):
        if x % i == 0:
            divisors.append(i)
    return divisors

# function to find random generator of G
def find_generator(p):
    # The order of any element in a group can be divided by p-1.
    # Step 1: Calculate all Divisors.
    # Step 2: Test for a random element e of G wether e to the power of a Divisor is 1.
    #           if neither is one but e to the power of p-1, a generator is found.


    # Init
    # Generate element which is tested for generator characteristics.
    # Saved in list to prevent checking the same element twice.
    testGen = randint(1,p)
    listTested = []
    listTested.append(testGen)
    # Step 1.
    divisors = find_divisors(p)

    # try for all random numbers
    # Caution: this leads to a truly random generator but is not very efficient.
    while len(listTested) < p-1:
        # only test each possible generator once
        if testGen in listTested:
            # Step 2.
            for div in divisors:
                testPotency = math.pow(testGen,div) % (p+1)
                if testPotency == 1.0 and div != divisors[-1]:
                    # element does not have the same order like the group,
                    # therefore try next element
                    break
                elif testPotency == 1.0 and div == divisors[-1]:
                    # generator is found
                    return testGen
        # try new element
        testGen = randint(1,p)
        listTested.append(testGen)

# ----------- HELPER FUNCTIONS ----------- 


# output: pp = (lamdba, q, G, H, H2) with
# q is prime
# g is generator of G
# G is multiplicative Group with prime order q
# H1 and H2 are two Hash functions H1: {0,1}* -> G
# (as well as H2: {0,1}* -> Zq which is the same).

# set prime p (Sophie-Germain and therefore save)
q = 53
# find random generator of G
g = find_generator(q-1)

# hash functions with desired range and the usage of secure hashes
h1 = lambda x: int(hashlib.sha256(str(x).encode()).hexdigest(),16)%(q)
# this way to share the information should be improved
h2 = lambda x: int(hashlib.sha512(str(x).encode()).hexdigest(),16)%(q)

# list of public keys
Rp = list()


class UniqueRingSignature(AbstractRingSignatureScheme):

    @staticmethod
    def keygen():
        print("---- KeyGen Started  ---- \n")
        r = randint(1,q)
        # x = g**r % q
        x = pow(g, r,q)

        # y = g**x
        y = pow(g, x, q)
        
        print("KeyGen Config: public key y=" + str(y) + ", private key x=" + str(x) + "\n")
        print("---- KeyGen Completed ---- \n")
        # Caution! I know, keygen should NOT return the private key, but this is needed to "play" through a whole signature - validation process
        return x,y
    
    @staticmethod
    def ringsign(x, R, message):
        print(R)
        #print("---- RingSign Started for user " + str(usernr) + " ---- \n")
        # input: privkey from user i, 
        #       usernumber: usernr
        #       all public keys: pubkeys
        #       the message
        # 
        # output: (R,m, (H(mR)^xi), c1,t1,...,cn,tn)
        #       R: all the pubkeys concatenated
        #       cj,tj: random number within Zq
        # 

        # calculate R = pk1,pk2,..,pkn
      
        # message + pubkeys concatenated
        mR = message + str(R)

        C = list()
        T = list()
        A = list()
        B = list()
        ri = -1

        # simulation step
        #
        for i in R:
            # Step 1:
            # 
            a = 0 
            b = 0
            c = 0
            t = 0
            if pow(g,x,q) != i:
                c, t = randint(1,q), randint(1,q)
                # aj = g^tj * y^cj
                a = (pow(g, t) * pow(i, c)) % q
                # bj = h(mR)^tj * (h(mR)^xi)^cj
                b = (pow(h1(mR), t) * pow(pow(h1(mR),privkey),c)) % q
            else:
                # Step 2:
                # 
                ri = randint(1, q)
                # ai = g^ri
                a = pow(g, ri, q)
                # bi = h(mR)^ri
                b = pow(h1(mR), ri, q)
                
                # insert to allocate place
                c = -1
                t = -1

            A.append(a)
            B.append(b)
            C.append(c)
            T.append(t)
        # for end

        # Step 3:
        # 
        ab = ""
        cj = 0

        # list count from 0
        # ab = {aj, bj} 1-> n
        for i in range(len(A)):
            ab = ab + str(A[i]) + str(B[i])

        usernr = 0
        # sum( cj % q ) ; for all j != i
        for i in range(len(R)):
            if x != (pow(g,R[i],q)):
                cj = (cj + C[i]) % q
            else: 
                usernr = i
                
        # ci = h'(m,R,ab) - sum(cj % q)
        ci = (h2(message + str(R) + ab) - cj) % q
        #ci = (h2 - cj) % self.pp['q']
        
        # update ci, this was initialized with -1
        C[usernr] = ci

        # ti = ri - (ci * xi % q )
        ti = (ri - (C[usernr]*x) % (q-1))
        if ti < 0:
                ti = (q-1) + ti
                
        # update ti, this was initialized with -1
        T[usernr] = ti

        # Step 4:
        # 
        # concatenate ct: c1,t1,c2,t2,...,cn,tn
        ct = ""
        for i in range(len(R)):
            ct = ct +","+ str(C[i])+"," + str(T[i])
        print("RingSign Result: " + str(R)+","+message+","+str(pow(h1(mR), \
                                                            x, q)) + ct + "\n")

        print("---- RingSign Completed ---- \n")
        return (str(R)+","+message+","+str(pow(h1(mR), x, q)) + ct)


    @staticmethod
    def verify(R, message, signature):
        print("---- Validation Started ---- \n")
        # parse the signature
        parsed = signature.split(",")
        tt = int(parsed[2])
        cjs = list()
        tjs = list()
        for i in range(0,int(((len(parsed))/2)-1)):
            cjs.append(int(parsed[3+2*i]))
            tjs.append(int(parsed[4+2*i]))

        # check signature
        # sum of all cjs
        # =?
        # self.pp['h2'](message + R + gyh1)

        val1 = sum(cjs) % q
        # for all users in R:
        # g**tj * yj ** cj , h1(m||R)**tj * tt**cj
        gyh1 = ""
        for i in range(len(tjs)):
            gyh1 = gyh1 + \
                   str( (pow(g,tjs[i]) * pow(R[i],cjs[i])) % q) + \
                   str( (pow(int(h1(message + str(R))), tjs[i]) * pow(tt,cjs[i]) ) % q)                                                                  
        val2 = str(h2(message + str(R) + gyh1))                                                           
        if int(val1) == int(val2):
            print("Signature is valid!\n")
            print("Common Result: " + str(val1))
            print("---- Validation Completed ---- \n")
            return True
        else:
            print("Signature is not valid!\n")
            print(str(val1) + " != " + str(val2))
            print("---- Validation Completed ---- \n")
            return False                                                              
                                                                           
 
if __name__ == '__main__':
    # user 1 will signate and validate later,
    # therefore his private key is saved for test purposes
    privKey1,pubkey = UniqueRingSignature.keygen()
    Rp.append(pubkey)

    # usernr start from 0
    # ringsign(self, privkey, usernr, pubkeys, message)
    ring = UniqueRingSignature.ringsign(privKey1, Rp, "asdf")
    print("Result of Signature Validation:")
    # verify(pubkeys, message, signature):
    UniqueRingSignature.verify(Rp, "asdf", ring)
