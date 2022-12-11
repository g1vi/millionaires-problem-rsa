# import libs
import random
import itertools
from Crypto.PublicKey import RSA
from Crypto.Util import number

class Millionaire:
 
    def __init__(self,num_million,max_million,num_bits):

        import time
        
        time.clock=time.time
        self.num_million=num_million
        self.max_million=max_million
        self.num_bits=num_bits
        self.keys=RSA.generate(2048)      
        self.privkey=self.keys.exportKey('PEM')
        self.pubkey=self.keys.publickey().exportKey('PEM')
 
    def get_pub_key_pem(self):
        
        return self.pubkey

    def get_ciphertext(self,peer_key_pem):

        peer_key=RSA.importKey(peer_key_pem)
        self.ta=random.getrandbits(self.num_bits)
        self.ka=peer_key.encrypt(self.ta,1)
        ciphertext=self.ka[0]-self.num_million
        return ciphertext
    
    def get_batch_z(self,ciphertext):
        
        self.priv_key=RSA.importKey(self.privkey)
        fi=[self.priv_key.decrypt(ciphertext+i) for i in range(self.max_million)]

        go_ahead=False
        while go_ahead==False:
            p=number.getPrime(self.num_bits)
            gi=[fi[i]%p for i in range(self.max_million)]
            # call itertools.combinations to get all combinations of 2 items in gi
            gi_pairs=itertools.combinations(gi,2) 
            diff=[(abs(i[0]-i[1])) for i in gi_pairs]
            for i in diff:
                if i<2:
                    go_ahead=False
                else:
                    go_ahead=True
                    
        Gi_1=[gi[i] for i in range(self.num_million)]
        Gi_2=[gi[j]+1 for j in range(self.num_million,self.max_million)]
        Gi=Gi_1+Gi_2
        Gi.append(p)
        
        return p,Gi
    
    def peer_is_richer(self, p, batch_z):
        
        m=self.ta%p
        if (batch_z[self.num_million]==m):
            return True
        else:
            return False

# PoC
# bob 49M, alice 40M, eve 30M, mallory 20M
bob=Millionaire(49,50,1024)
alice=Millionaire(40,50,1024)
eve=Millionaire(30,50,1024)
mallory=Millionaire(20,50,1024)

alice_pubkey=alice.get_pub_key_pem()
bob_pubkey=bob.get_pub_key_pem()
eve_pubkey=eve.get_pub_key_pem()
mallory_pubkey=mallory.get_pub_key_pem()

alice_ciphertext=alice.get_ciphertext(bob_pubkey)
bob_ciphertext=bob.get_ciphertext(eve_pubkey)
eve_ciphertext=eve.get_ciphertext(mallory_pubkey)
mallory_ciphertext=mallory.get_ciphertext(alice_pubkey)

p1,G1=bob.get_batch_z(alice_ciphertext)
p2,G2=eve.get_batch_z(bob_ciphertext)
p3,G3=mallory.get_batch_z(eve_ciphertext)
p4,G4=alice.get_batch_z(mallory_ciphertext)

if (alice.peer_is_richer(p1,G1)):
    print("bob is richer than alice")
else:
    print("alice is richer than bob")

if (bob.peer_is_richer(p2,G2)):
    print("eve is richer than bob")
else:
    print("bob is richer than eve")

if (eve.peer_is_richer(p3,G3)):
    print("mallory is richer than eve")
else:
    print("eve is richer than mallory")
    
if (mallory.peer_is_richer(p4,G4)):
    print("alice is richer than mallory")
else:
    print("mallory is richer than alice")
