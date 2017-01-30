# import hashlib
# import gmpy2
# from random import randint
# import RSAsig
# 
# class LWW(AbstractRingSignatureScheme):
#         g = 10 #?
#         q #Primzahl
#         n = 10#Anzahl User
# 
#         def H1(x):
#                 y = hashlib.sha512(x)
#                 z = y % q
#                 return z
# 
#         def H2(x):
#                 y = hashlib.sha3_512(x)
#                 z = 0#?
#                 return z
# 	
#         def generatorDummie():
#                 listKeys = []
#                 for i in range(n):
#                         x = randint(1,q-1)
#                         y = pow(g, x, q)
#                         b = [y,x]
#                         listKeys.append(b)
# 	
#                 userIndexi = randint(1,n)
#                 useri = listkey[userIndexi-1]
# 
#                 keys = []
#                 for i in range(0,len(listKeys)):
#                         keys.append(listKeys[i][0])
# 
#                 return [keys, useri[1]]
# 
#         def checkWhichUser(privUser, L):
#                 tmp = pow(g,privUser,q)
#                 for i in range(0,len(L)):
#                         if tmp == L[i]:
#                                 userIndex = i + 1
#                                 break
#                 return userIndex
# 
#         # ------ Anfang -----
# 
#         tmp = generatorDummie()
#         print(tmp)
#         L = tmp[0]
#         privKeyUser = tmp[1]
#         message = "Hallo"
#         
#         def ringsign(privKeyUser, L, message):
#                 
#                 #Check which user we are
#                 userIndex = chechWhichUser(privKeyUser, keys)
# 
#                 #Part 1
#                 h = H2(str(L))
#                 ytilde = pow(h,privKeyUser, q)
# 
#                 #Part 2
#                 u = randint(1,q-1)
#                 K = L
#                 K.append(ytilde)
#                 K.append(message)
#                 K.append(pow(g,u,q))
#                 K.append(pow(h,u,q))
#                 c = H1(str(K))
#                 
#                 #Part 3                
#                 c1 = 0
#                 s = range(0:len(L))
#                 for i in range(1,len(L)):
#                         j = (i+userIndex)%len(L)
#                         if j == 1
#                                 c1 = c
#                         si = randint(1,q-1)
#                         s[j-1] = si
#                         K = L
#                         K.append(ytilde)
#                         K.append(message)
#                         K.append(pow(g,si,q)*pow(L[j],c,q))
#                         K.append(pow(h,si,q)*pow(ytilde,c,q))
#                         c = H1(str(K))                       
# 
#                 #Part 4
#                 s[userIndex-1] = (u - c*privKeyUser) % q
# 
#                 #Finish
#                 Sig = []
#                 Sig.append(c1)
#                 Sig.append(s)
#                 sig.append(ytilde)
#                 
#                 
# 
#         def verify(pubkeys, message, signature):
# 
#                 #Part 1
#                 c = signature[0]
#                 h = H2(str(pubkeys))
#                 z1 = 0
#                 z2 = 0
#                 K = []
#                 for i in range(1,len(pubkeys)+1):                        
#                         z1 = pow(g,signature[i],q)*pow(pubkeys[i-1],c,q)
#                         z2 = pow(h,signature[i],q)*pow(signature[len(signature)-1],c,q)
# 
#                         K = pubkeys
#                         K.append(signature[len(signature)-1])
#                         K.append(message)
#                         K.append(z1)
#                         K.append(z2)
#                         c = H1(str(K))
# 
#                 #Part 2
#                 if signature[0] == c
#                         return True
#                 else
#                         return False
# 
#                         
# 
