import json
from telnetlib import Telnet

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Util.number import *
import math #allowed because it's part of standard library

# IMPORTANT: Change this to False if you want to run the client against your local implementation
REMOTE = True

#note to ta: big comment section starts after the get flag method (after line 400)
#details in appripriate methods

#just reuse M4.0 for code.
#int.from_bytes(bytes, 'big') : bytes -> big endian conversion; cryptodome says that; it also says that the eqivalent to that is bytes_to_long(bytes)

#some additional methods used to implement sign, encode and verify
def rsavp1(n, e, s):
    #assume no error occurs
    #so step 1 is okay
    
    #step 2
    m = pow(s, e, n)
    
    #step 3
    return m
    
def i2osp(s: int, k: int) -> bytes:
    #https://datatracker.ietf.org/doc/html/rfc8017#section-4.1
    #assume there is no error encountered, that is s is not too large.
    S = long_to_bytes(s)
    to_pad_length = len(S) - k
    if to_pad_length > 0:
        S = S + bytes([0]) * to_pad_length
    return S
    
def rsasp1(K: RSA.RsaKey, m: int) -> int:
    #https://datatracker.ietf.org/doc/html/rfc8017#section-5.2.1
    #Assume that K is a pair (n, d), since we don't have the other information to make a quintuple
    
    #setup - step 0
    n = K.n
    d = K.d
    
    #step 1, assume that m is in range between 0 and n - 1
    
    #step 2
    s = pow(m,d,n)
    #step 3
    return s

#encode re-checked
def encode(m: bytes, emLen: int) -> bytes:
        """ Custom EMSA-PKCS1-v1_5-style encoding.
        Follow the rfc8017 section 9.2, with the following exceptions:
        - always use SHA256 as the Hash,
        - discard step 2:
            - let T be (0x) 63 61 72 70 65 74 || H,
            - and tLen be the length in bytes of T.

        If you want to test your implementation against pycryptodome's pkcs1 v1.5 signatures,
        temporarily let T be (0x)30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 || H.
        Note: that "octet" = byte, "octet string" = bytes object

        Args:
                M (bytes): message to be encoded
                emLen (int): intended length in bytes of the encoded message, as per rfc8017

        Returns:
                EM: encoded message, a bytes object of length emLen
        """
        '''
        emLen    intended length in octets of the encoded message, at
                            least tLen + 11, where tLen is the octet length of the
                            Distinguished Encoding Rules (DER) encoding T of
                            a certain value computed during the encoding operation
        '''
        #implementation idea: Follow the rfc8017 section 9.2, with the exception named above
                
        #setup - step 0
        hash256 = SHA256.new()
        T_values = b'\x63\x61\x72\x70\x65\x74'
        #T_values = b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20'
        #step 1
        
        hash256.update(m)
        H = bytes.fromhex(hash256.hexdigest())
        #step 2
        #omit by comment above
        
        #step 3
        T = T_values + H
        tlen = len(T)
        '''
        If emLen < tLen + 11, output "intended encoded message length too short" and stop.
        Let's assume this does not occur. Turns out this is not a problem when testing.
        '''
        
        #step 4
        length = emLen - tlen - 3
        PS = bytes([255]) * length
        '''
        The length of PS will be at least 8 octets.
        Let's assume this holds. Turns out this is not a problem when testing.
        '''
        #step 5
        EM = bytes([0]) + bytes([1]) + PS + bytes([0]) + T
        
        #step 6
        return EM
        #raise NotImplementedError

#re-check
def sign(K: RSA.RsaKey, M: bytes) -> bytes:
        """ Custom RSASSA-PKCS1-v1_5 (RSA Signature Scheme with Appendix)-style signature generation.
        Follow the rfc8017 section 8.2.1, with the following exception:
        - use the custom EMSA-PKCS1-v1_5-style encoding instead of the one specified in the standard.

        Args:
                K (RSA.RsaKey): signer's RSA private key.
                M (bytes): message to be signed.

        Returns:
                (bytes): encoded message, a bytes object of length emLen.
        """
        
        
        '''
        Idea: I just follow the instructions, given here.
        Follow the rfc8017 section 8.2.1, with the following exception:
        - use the custom EMSA-PKCS1-v1_5-style encoding instead of the one specified in the standard.
        '''
        
        #setup - step0
        k = len(long_to_bytes(K.n)) #checked
        #step 1
        EM = encode(M, k)
        '''
        If the encoding operation outputs "message too long", output
                            "message too long" and stop.  If the encoding operation
                            outputs "intended encoded message length too short", output
                            "RSA modulus too short" and stop.
        Let's assume everything works fine. Turns out this is not a problem when testing.
        '''
        #step 2
        
        #step 2a
        '''
        Convert the encoded message EM to an integer message representative m = OS2IP (EM)
        '''
        m = bytes_to_long(EM) #this method is equivalent to the one on the right. int.from_bytes(EM, 'big') #OS2IP
        
        #step 2b
        '''
        Apply the RSASP1 signature primitive (Section 5.2.1) to the RSA private key K and the message representative m to produce an integer signature representative s = RSASP1 (K, m).
        '''
        s = rsasp1(K, m) 
        #step 2c
        
        '''
        Convert the signature representative s to a signature S of length k octets (see Section 4.1): S = I2OSP (s, k).
        '''
        S = i2osp(s, k) #equivalent to long_to_bytes(s, k); see #https://pycryptodome.readthedocs.io/en/latest/src/util/util.html#Crypto.Util.number.long_to_bytes; #S = i2osp(s, k)
        
        #step 3
        return S
        #raise NotImplementedError

#to check
def verify(N: int, e: int, M: bytes, S: bytes) -> bool:
        """ Custom RSASSA-PKCS1-v1_5 (RSA Signature Scheme with Appendix)-style signature verification.
        Follow the rfc8017 section 8.2.2, with the following exception:
        - use the custom EMSA-PKCS1-v1_5-style encoding instead of the one specified in the standard.

        Args:
                N, e: signer's RSA public key
                M (bytes): message whose signature is to be verified.
                S (bytes): signature to be verified, an bytes object of length k,
                                     where k is the length in bytes of the RSA modulus n.

        Returns:
                (bool): True iif the signature is valid.
        """
        
        '''
        Idea: I just follow the instructions given here.
        Follow the rfc8017 section 8.2.2, with the following exception:
        - use the custom EMSA-PKCS1-v1_5-style encoding instead of the one specified in the standard.
        '''
        
        '''
        Assume errors do not occur, that is that in step 1 of rfc8017 section 8.2.2, valid inputs. Turns out this is not a problem when testing.
        '''
        
        #step 0 - setup
        k = len(long_to_bytes(N))
        
        #step 1 - assumed to be correct length
        
        #step 2
        
        #step 2a
        s = bytes_to_long(S) # this is equivalent to the methods used on the right int.from_bytes(S, 'big') #OS2IP
        
        #step 2b
        m = rsavp1(N, e, s) #slight abuse of notation when compared to https://datatracker.ietf.org/doc/html/rfc8017#section-8.2.2; pow(s, e, N)
        
        #step 2c, assume no error occurs here; Turns out this is not a problem when testing.
        EM = long_to_bytes(m, k) #equivalent to i2osp(m, k)
        
        #step 3
        EM_primed = encode(M, k)
        
        #step 4
        #print(EM)
        #print(EM_primed)
        return EM == EM_primed
        
        #raise NotImplementedError

class CarpetRemote():
    def __init__(self, tn: Telnet, carpet_key: RSA.RsaKey, cloud_key: RSA.RsaKey):
        self.tn = tn
        self.carpet_key = carpet_key
        self.cloud_key = cloud_key

    def json_recv(self):
        line = self.tn.read_until(b"\n")
        return json.loads(line.decode())

    def json_send(self, req: dict):
        request = json.dumps(req).encode()
        self.tn.write(request + b"\n")
    
    #gives me the public key
    def save_config(self):
        obj = {
            "msg": {
                "command": "save_config",
            },
            "identity": "carpet_cloud",
            "signature": "00"
        }
        self.json_send(obj)
        res = self.json_recv()
        signed_res = res["signed_res"]

        pub_cfg, priv_cfg = signed_res["pub_cfg"], signed_res["priv_cfg"]
        #debugging
#        print("N: ", end="")
#        print(pub_cfg["n"])
#        
#        print("e: ", end="")
#        print(pub_cfg["e"])
#        
#        print("nonce: ", end="")
#        print(bytes.fromhex(priv_cfg["nonce"]))
#        
#        print("ciphertext: ", end="")
#        print(bytes.fromhex(priv_cfg["ciphertext"]))
#        
#        print("tag: ", end="")
#        print(bytes.fromhex(priv_cfg["tag"]))
        
        return (
            (pub_cfg["n"], pub_cfg["e"]),
            (bytes.fromhex(priv_cfg["nonce"]),
                bytes.fromhex(priv_cfg["ciphertext"]),
                bytes.fromhex(priv_cfg["tag"])))

    def restore_config(self, pub_cfg, priv_cfg):
        n, e = pub_cfg
        nonce, ciphertext, tag = priv_cfg

        obj = {
            "msg": {
                "command": "restore_config",
                "pub_cfg": {
                    "n": n,
                    "e": e
                },
                "priv_cfg": {
                    "nonce": nonce.hex(),
                    "ciphertext": ciphertext.hex(),
                    "tag": tag.hex()
                },
            },
            "identity": "carpet_cloud",
            "signature": "00"
        }

        self.json_send(obj)
        res = self.json_recv()

        return (res["signed_res"],
            bytes.fromhex(res["signature"]))

    def factory_config(self):
        obj = {
            "msg": {
                "command": "factory_config",
            },
            "identity": "carpet_cloud",
            "signature": "00"
        }

        self.json_send(obj)
        res = self.json_recv()

        return (res["signed_res"],
            bytes.fromhex(res["signature"]))
        
#    def json_signed_send(self, req: dict):
#        signature = sign(self.cloud_key, json.dumps(req).encode())
#        self.json_send({
#            "identity": "carpet_cloud",
#            "msg": req,
#            "signature": signature.hex()
#        })
#
#    def json_signed_recv(self):
#        res = self.json_recv()
#        signature = bytes.fromhex(res["signature"])
#        
#        #print("json_signed_recv -> signature: ", end="")
#        #print(signature)
#
#        if "signed_res" in res:
#            signed = json.dumps(res["signed_res"]).encode()
#        else:
#            signed = res["signed_error"].encode()
#
#        if verify(self.carpet_key.n, self.carpet_key.e, signed, signature):
#            print("Verification passed.")
#            return signed
#        return "VERIFY FAILED"    
       
    
    def get_status(self):
        print("Call get_status")
        #get status function
        obj = {
            "msg": {
                "command": "status",
            },
            "identity": "carpet",
            "signature": '00'
        }

        self.json_send(obj)
        res = self.json_recv()
        print(res)
        return res
             
    def get_flag(self, secret_d, rsa_modulus):
        
        #in attack, we established that we need to sign the
        #corresponding json.dumps(command_here).encode()
        
        M = json.dumps({"command": "backdoor"}).encode()
        
        #inplace signing
        k = len(long_to_bytes(rsa_modulus))
        EM = encode(M, k)
        m = bytes_to_long(EM) 
        s = pow(m, secret_d, rsa_modulus)
        S = long_to_bytes(s, k)
        
        signature = S.hex()
        
        obj = {
            "msg": {
                "command": "backdoor",
            },
            "identity": "carpet",
            "signature": signature
        }

        self.json_send(obj)
        res = self.json_recv()

        return res
        #return (res["signed_res"], bytes.fromhex(res["signature"]))
            

'''
This is my place to think and write down thoughts and observations.

Overview about keys used by server:
    
When instantiate server object, the following keys are given as arguemtents:
carpet_test_key,
cloud_test_key,
get_random_bytes(16)

they instantiate. the keys of the server object in the following way:
key: RSA.RsaKey,
cloud_key: RSA.RsaKey,
config_key: bytes,

by: super().__init__(key=key, cloud_key=cloud_key, config_key=config_key, flag=flag)
instantiate SmartCarpet object in the following way
    
self.skey = key                 [carpet_test_key]
self.factory_skey = key         [carpet_test_key]
self.config_key = config_key    #random 16 bytes key [get_random_bytes(16)]
self.trusted_entities = 
{
    "carpet": self.skey,         [carpet_test_key]
    "carpet_cloud": cloud_key,    [cloud_test_key]
}

Purpose of keys:
cloud_test_key: When identity is carpet_cloud, we use this key to verify a signature
    
carpet_test_key: (used by server as self.skey ). It's the key that, next to its public components, has the corresponding secret components. Also used to sign responses in the try branch of exec_command_secure (and in except branch)
    
self.config_key: random 16 bytes key. Used in save_config, when saving configurations, to encrypt information about they private key (e.g. d, prime factorization, etc.). The key in question is self.skey, which is carpet_test_key. 

Note that self.factory_skey


In client code, only the public components are known. The random key is not known (it's only on the server side).



Observe: In exec_command_secure,
When msg["command"] in ["save_config", "restore_config", "factory_config"], then there is no check of signature validity.
else, there is a check.

Since we can also choose which identity the client uses, it is possible to tell the server which (private) key to use to check the signature.

Note that no matter is sent by the server (either try or except branch), the signature is always computed using the (private part of) self.skey, which is the carpet_test_key (associated with identity "carpet"). So I, the client, will always get a message, signed with carpet_test_key.

This means that we never get to see a signature produced by using the cloud_key (associated with identity "carpet_cloud")
-> dead-end when using "carpet_cloud" as identity -> when query commands, use identity "carpet"


Server side - Config methods: command = 

save_config: This gives us back the current self.skey in use (of course secret key parameters encrypted) - with save, it means that a copy of the current self.skey is stored at the client side. This means that we get to see the public key parameters of self.skey. [Marked as IMPORTANT]

restore_config: Given key parameters, provided by the client, and encrypted private key parameters, set the key to that. Note that no consistency check is made. (see below)

factory_config: Reset self.skey to self.factory_skey (and set warrant_void = false)



Observe: In factory_config, we have the following:
    self.warranty_void = False
    self.skey = self.factory_skey
[IMPORTANT] Looking at the server code, self.factory_skey is never modified again after instantiation. I think this for factory resetting the key

[IMPORTANT] It is important that, when we get the flag, warranty_void is False.


Observe: In restore_config, consistency_check is set to False, so by https://pycryptodome.readthedocs.io/en/latest/src/public_key/rsa.html, no need to check if the parameters given satisfay the main RSA properties. What is mean by that can be seen in the implementation, linked below. 
https://github.com/Legrandin/pycryptodome/blob/master/lib/Crypto/PublicKey/RSA.py#L580
So it does not check if
# Modulus and private exponent must be coprime
# Modulus must be product of 2 primes
# p * q = n
# p, q primes
# and more

Maybe we can exploit this.



We use the hints given for this task we find
https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm

In group theory, the Pohlig–Hellman algorithm, sometimes credited as the Silver–Pohlig–Hellman algorithm,[1] is a special-purpose algorithm for computing discrete logarithms in a finite abelian group whose order is a smooth integer.

https://en.wikipedia.org/wiki/Smooth_number
Smooth integer: A natural number k is n-smooth if all of its prime factors are <= n.

The Twitter links leads to https://www.kopenpgp.com/.
We find under attack vectors something that might be salvagable: 1) Secret key extraction attacks. 
Here the excerpt:
---------------
In this case, the attacker aims to overwrite the public key parameters in the victim’s encrypted private key, so that when the victim uses it e.g. to sign something, the resulting faulty signature will leak at least partial information about the original secret key parameters.

We have found that all key types are potentially vulnerable to secret key extraction: in RSA and DSA, a single faulty signature is sufficient to reconstruct the secret exponent [...]
---------------
We find the full details in the following paper: https://www.kopenpgp.com/assets/paper.pdf
Section 3 goes more into detail about Secret key extraction attacks.

Under 3.3.4, we find a possible approach (that has something about RSA).
1) replace server side RSA modulus N with N' for which phi(N') is smooth
2) s' = m^d mod N'
    m element of ZN'*, large enough ord_N'(m) >= d.
3) compute d via Pohlig Hellman algorithm

    
Ultimate goal: I want to issue the flag command to get the flag. Problem: In order to do so, we need a valid signature for the flag command -> since we only have public key parameters, (and no secret key), we need to find the secret key. We target self.skey (associated with identity "carpet", key is self.skey = carpet_test_key)


Idea - derived from all information above
1) generate prime N' large enough (of bitsize >= bitsize N, the server RSA modulus)
    - compute primes of bitsize 20 (or so)
    - compute power of 2 such that resulting N' is an odd prime
2) set N' as the new RSA modulus on server side
3) request signature s = m^d mod N'
    find what m is (via server response, see below)
    hopefully, m (as integer) is an element of Z_k*, where k = N' -> m is a generator of that group.
4) compute d via Pohlig–Hellman_algorithm 
5) reset server RSA modulus to N (original server RSA modulus)
6) sign with d own command flag query and get flag

'''

#used to check if the primes generated are truly unique
#helper function for debugging.
def check_uniqueness(output):
    list_of_primes, _, _, _ = output
    #check if list contains no duplicate primes
    length_of_list = len(list_of_primes)
    len_of_set = len(set(list_of_primes)) #use set to remove duplicates
    #print(length_of_list) #should output 108 for current output used below
    print(len_of_set) #should output 108 for current output used below
    #if both numbers are equal -> no duplicate primes in list
    return (length_of_list == len_of_set)
    
def generate_N_primed_():
    print("Called: generate_N_primed_")
    #see below how I generated this output
    #I hardcoded this precomputed output to save time
    #note that this is alright, because the server RSA modulus is independent (and by moodle post, rsa modulus will remain of bitsize 2048) from this new Rsa modulus here; the chosen rsa modulus has bitsize 2160 bits.
    output = ([2, 672901, 755171, 822293, 679561, 619657, 904261, 972649, 598721, 601487, 589409, 641129, 834761, 955037, 844469, 632881, 710081, 895703, 747811, 955807, 750383, 1004599, 828557, 710627, 783077, 1010353, 1036493, 641491, 680929, 1016401, 925637, 772451, 908287, 918767, 579947, 984241, 830339, 755899, 638303, 896191, 852989, 883307, 689951, 532069, 568963, 932207, 694259, 550163, 847339, 1031999, 628423, 542567, 728173, 566161, 909791, 592073, 657649, 807403, 728891, 755203, 866477, 995081, 719801, 850021, 706267, 820231, 995983, 525163, 880661, 542981, 758267, 709097, 1044079, 757879, 632669, 782009, 845927, 1035949, 969721, 743573, 1012559, 588743, 804473, 953983, 820873, 772313, 822517, 703819, 893059, 652153, 788687, 1024663, 552397, 925271, 1026073, 703903, 756641, 848201, 1025789, 821603, 553667, 733619, 941791, 573409, 907733, 782981, 679297, 774313, 1036991, 570937, 1032793, 1022381, 640411, 1048213, 855601, 631619, 909329, 636749, 968537, 974957, 548687, 693223, 1014089, 586679], [18, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1], 8459708583964837330826306344857079953185543080031587369303004091460952480865970074082745961953959105113751587953055701767575092591191811584504490134117057969986505546977616080911908494739000847303537518270757258364704766894575418225506168500484926112939892324574987314032007000457702962836751133314581337203163551491680428668298449305224104539705862099353481920591664387475299886834670678305354093684477587302591125775594870248988479159952545674365513087325905594170883280357152317454190606672913188850154913184571078760608649598921857468564149746680875969628519581332299451477361817566957105231720980467199763648467252296568027667783040166059303177374479914602004692913975941041349130291641357011418033285535239757928202359799809, 8459708583964837330826306344857079953185543080031587369303004091460952480865970074082745961953959105113751587953055701767575092591191811584504490134117057969986505546977616080911908494739000847303537518270757258364704766894575418225506168500484926112939892324574987314032007000457702962836751133314581337203163551491680428668298449305224104539705862099353481920591664387475299886834670678305354093684477587302591125775594870248988479159952545674365513087325905594170883280357152317454190606672913188850154913184571078760608649598921857468564149746680875969628519581332299451477361817566957105231720980467199763648467252296568027667783040166059303177374479914602004692913975941041349130291641357011418033285535239757928202359799808) #124 unique primes
    #for debugging
#    if not check_uniqueness(output):
#        print("NOT UNIQUE PRIMES -> GENERATE NEW LIST")
    return output
    
    #I commented out the out below
    
    '''
    
    #generate N' such that N' is prime and we know the factorization of N' - 1 = phi(N') (euler toitient)
    #N' should also be of 2048 bits, like the original RSA modulus
    #I imagine that the system of congruence quations we get (after Pohlig-Hellmann and have to apply CRT to) must contain enough information to solve for d. I think 2048 bits ro more should be sufficient.
    #In paper, mid sized primes factors should be of roughly 20 bits.
    #this gives us a pointer how big the prime factors of N' - 1 = phi(N') should be.
    number_of_primes = math.ceil(2048 / 20) + 20 #need to have enough primes -> I tested this.
    prime_list = [0] * (number_of_primes + 1) #first entry is for prime 2, others are odd random primes of bitsize 20 
    exponent_list = [1] * (number_of_primes + 1) #all exponents after the first one (first prime = 2) is set to 1 #see below
    
    prime_list[0] = 2
    #exponent_list[0] = 10 #for debugging hardcoded, want baby_step_giant_step to run fast so low exponent
    #phi_of_N_primed = 1 #product of prime (powers)
    
    
    #we know that pohlig hellmann performs baby step giant step algorithm, which searches from the space {0, 1, ..., p_i^e_i}, where p_i is a prime factor of N' - 1 (with the corresponding power e_i) -> set want low exponents to speed up and minimize search space and save time when performingbaby step giant step algorithm
        #recall that what we aim is: N' prime and phi(N') = N' - 1 smooth, since N' is at least a 2048 number, N' is an odd prime -> N' - 1 is even -> so it contains powers of 2.
        #we have to find the power of 2, e_1, such that 2^e_1 * (product of prime factors chosen) + 1 is a prime, which we select to be the N'
        #we aim to find a small e_1 to speed up baby step giant step algorithm
        #we set all other exponents to 1
    
    #temp = pow(prime_list[0], exponent_list[0]) 
    
    while True:
        for k in range(1, 20):
            print("Generating prime: " + str(k))
            exponent_list[0] = k
            phi_of_N_primed = pow(prime_list[0], exponent_list[0])
            for i in range(1, number_of_primes + 1):
                cur_prime = getPrime(20)
                phi_of_N_primed *= cur_prime
                prime_list[i] = cur_prime
            N_primed = phi_of_N_primed + 1
            #tradeoff lower false_positive_prob for time efficiency
            if isPrime(N_primed, false_positive_prob=1e-100):
                return (prime_list, exponent_list, N_primed, phi_of_N_primed)
                    #N_primed is most likely a prime
                    #we know prime factorisation of phi_of_N_primed = N_primed - 1
                    #hopefully, this is smooth
                    #N_primed is at least a 2048 bit prime
                    
    '''

#works
def chinese_remainder_theorem(r_values_list, prime_power_list, phi_N_primed):
    #for convience, to avoid multiplying all prime powers again
    #why it is implemented they way it is: It's from Diskmat - undergrad lecture
    print("Called: chinese_remainder_theorem")
    M = phi_N_primed
    
    len_prime_power_list = len(prime_power_list)
    
    M_i_list = [0] * len_prime_power_list
    for i in range(len_prime_power_list):
        M_i_list[i] = M // prime_power_list[i]
        
    #gcd(M_i_list[i], prime_power_list[i]) = 1 for all prime_power_list[j], j not equal i because we divided away prime_power_list[i] from M, making them relative prime to each other (check prime facotirisation to see this)
    
    #then there ist N_i[i] such that M_i[i] * N_i[i] = 1 mod prime_power_list[i]
    #N_i[i] is just the mult. inverse of M_i[i] modulo prime_power_list[i]
    
    N_i_list = [0] * len_prime_power_list
    for i in range(len_prime_power_list):
        N_i_list[i] = inverse(M_i_list[i], prime_power_list[i])
    
    #sum together, take modulo phi_N_primed of end result -> we found the secret key
    d = 0
    for i in range(len_prime_power_list):
        d += r_values_list[i] * M_i_list[i] * N_i_list[i]
    
    return d % phi_N_primed

#Algorithm from:
#https://en.wikipedia.org/wiki/Baby-step_giant-step
def baby_step_giant_step(lhs_s_val_after_pow, rhs_m_val_after_pow, modulus, prime_power):
    print("Called: baby_step_giant_step")
    #m = prime_power
    #m = prime_power
    #actually, would need to insert here below euler_toitient(prime_power) because that's the order of the multiplicative group Zm*, where m = prime_power (but a little more does not hurt nor does it make the algorithm wrong)
    m = math.ceil(math.sqrt(prime_power))
    #do want to to use list to search through -> use hash map
    
    #consistency with wikipedia
    #beta = lhs_s_val_after_pow
    #alpha = rhs_m_val_after_pow
    
    #in python, we can directly use dictionary to perform this
    table = {}
    
    for j in range(m):
        table.update({pow(rhs_m_val_after_pow, j, modulus): j})
        
    #inverse of alpha
    inverse_rhs_m_val_after_pow = inverse(rhs_m_val_after_pow, modulus)
    
    #inverse_rhs_m_val_after_pow pow m
    inverse_pow_m = pow(inverse_rhs_m_val_after_pow, m, modulus)
    
    gamma = lhs_s_val_after_pow
    for i in range(m):
        #lookup in table
        if gamma in table:
            j = table[gamma]
            return (i * m + j)
        gamma = (gamma * inverse_pow_m) % modulus
        
    print('ERROR')
    return -1 #error
    
#algorithm from:    
#https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm
def pohlig_hellman_algorithm_general(list_of_primes, list_of_exponents, N_primed, phi_of_N_primed, sign_int, msg_int):
    print("Called: pohlig_hellman_algorithm_general")
    #we can use msg_int not equal to 0 as generator since N_primed is prime, hence for m:= N_primed, Zm* is cyclic and all its members are generators (because in Zm*, there are m - 1 elements since m prime) (and we checked in attack method that msg_int < N_primed [in debuggin])
    #we have signature_integer_value = message_integer_value ^ d mod N_primed
    #solve for d now.
    #we have phi_of_N_primed = N_primed - 1

    number_of_primes = len(list_of_primes)
    
    mapping = map(lambda p, e: pow(p, e), list_of_primes, list_of_exponents)
    prime_power_list = list(mapping)
#    print(prime_power_list)
    #print(type(prime_power_list))
    
    
    #for debugging
    '''
    #3 = 11^x mod 29
    #print(baby_step_giant_step(3, 11, 29, 29)) = 17
    #13 = 5 ^ x mod 37
    #print(baby_step_giant_step(13, 5, 37, 37)) = 13
    #28 = 2^n mod 37
    #print(baby_step_giant_step(28, 2, 37, 37)) = 34
    #print(baby_step_giant_step(3, 5, 23, 23)) = 16
    '''
    
    #for debugging
#    list_of_primes = [2,3,5,7]
#    list_of_exponents = [1,1,1,1]
#    N_primed = 211
#    phi_of_N_primed = 210
#    sign_int = 41
#    msg_int = 2
#    number_of_primes = len(list_of_primes)
#    mapping = map(lambda p, e: pow(p, e), list_of_primes, list_of_exponents)
#    prime_power_list = list(mapping)
#    phi_of_N_primed_without_1_prime_power = [0] * number_of_primes
    #first divide phi_of_N_primed by prime powers
    #checked
    
#    list_of_primes = [2,3,5]
#    list_of_exponents = [2,4,2]
#    N_primed = 8101
#    phi_of_N_primed = 8100
#    sign_int = 7531
#    msg_int = 6
#    number_of_primes = len(list_of_primes)
#    mapping = map(lambda p, e: pow(p, e), list_of_primes, list_of_exponents)
#    prime_power_list = list(mapping)
#    phi_of_N_primed_without_1_prime_power = [0] * number_of_primes
#    
    
#    list_of_primes = [2,3]
#    list_of_exponents = [4,3]
#    N_primed = 433
#    phi_of_N_primed = 432
#    sign_int = 166
#    msg_int = 7
#    number_of_primes = len(list_of_primes)
#    mapping = map(lambda p, e: pow(p, e), list_of_primes, list_of_exponents)
#    prime_power_list = list(mapping)
#    phi_of_N_primed_without_1_prime_power = [0] * number_of_primes
    
#    list_of_primes = [2,3,7]
#    list_of_exponents = [4,1,1]
#    N_primed = 337
#    phi_of_N_primed = 336
#    sign_int = 131
#    msg_int = 15
#    number_of_primes = len(list_of_primes)
#    mapping = map(lambda p, e: pow(p, e), list_of_primes, list_of_exponents)
#    prime_power_list = list(mapping)
#    phi_of_N_primed_without_1_prime_power = [0] * number_of_primes
    
    #28 = 2^x mod 37 correct
#    list_of_primes = [2,3]
#    list_of_exponents = [2,2]
#    N_primed = 37
#    phi_of_N_primed = 36
#    sign_int = 28
#    msg_int = 2
#    number_of_primes = len(list_of_primes)
#    mapping = map(lambda p, e: pow(p, e), list_of_primes, list_of_exponents)
#    prime_power_list = list(mapping)
#    phi_of_N_primed_without_1_prime_power = [0] * number_of_primes
    
    #210 = 71^x mod 251 correct
#    list_of_primes = [2,5]
#    list_of_exponents = [1,3]
#    N_primed = 251
#    phi_of_N_primed = 250
#    sign_int = 210
#    msg_int = 71
#    number_of_primes = len(list_of_primes)
#    mapping = map(lambda p, e: pow(p, e), list_of_primes, list_of_exponents)
#    prime_power_list = list(mapping)
#    phi_of_N_primed_without_1_prime_power = [0] * number_of_primes
    
    
    
    phi_of_N_primed_without_1_prime_power = [0] * number_of_primes #init
    #call elements of phi_of_N_primed_without_1_prime_power just alpha
    for i in range(number_of_primes):
        phi_of_N_primed_without_1_prime_power[i] = (phi_of_N_primed // prime_power_list[i])
    
    #print('DEBUG')
    print("phi_of_N_primed_without_1_prime_power")
    #print(phi_of_N_primed_without_1_prime_power)
    
    #s = m ^ d mod N'
    #build LHS
    lhs = [0] * number_of_primes
    for i in range(number_of_primes):
        lhs[i] = pow(sign_int, phi_of_N_primed_without_1_prime_power[i], N_primed)
    
    print("lsh")
    #print(lhs)
    
    #build rhs
    rhs = [0] * number_of_primes
    for i in range(number_of_primes):
        rhs[i] = pow(msg_int, phi_of_N_primed_without_1_prime_power[i], N_primed)
     
    print("rhs")   
    #print(rhs)
    
    r_values = [0] * number_of_primes
    
    #special case with 2^e_1
    #r_values[0] = pohlig_hellman_algorithm_special_case(2, list_of_exponents[0], prime_power_list[0], N_primed, phi_of_N_primed, sign_int, msg_int)
    
    for i in range(number_of_primes):
        r_values[i] = baby_step_giant_step(lhs[i], rhs[i], N_primed, prime_power_list[i])
        print(str(i) + ". congruence equation ready: " + "d = " + str(r_values[i]) + " mod " + str(prime_power_list[i]) + "")
    print("r_values")
    #print(r_values)
            
    #Chinese Remainder Theorem 
    d = chinese_remainder_theorem(r_values, prime_power_list, phi_of_N_primed)
    #print(d)
    print("Computed d is the correct solution: ", end="")
    print(sign_int == pow(msg_int, d, N_primed))
    return d
        
def attack(tn: Telnet, carpet_key: RSA.RsaKey, carpet_cloud_key: RSA.RsaKey):
    """ Your attack code goes here.
    """
        
    '''
    Idea - derived from all information above
    1) generate prime N' (of equal size as N, the server RSA modulus)
    2) set N' as the new RSA modulus on server side
    3) request signature s = m^d mod N'
        find what m due to server response (see below)
    4) compute d via Pohlig–Hellman_algorithm
    5) reset server RSA modulus to N (original server RSA modulus)
    6) sign with d own command flag query and get flag
    '''
    
#    print("CarpetRemote init")
#    cr = CarpetRemote(tn, carpet_key, carpet_cloud_key)
#    
#    print("save_config init")
#    (N, e), (nonce, ciphertext, tag) = cr.save_config()
#    
#    print("generate_N_primed_ init")
#    (primes_to_use_final, exponents_final, N_primed, phi_of_N_primed) = generate_N_primed_()
#    
#    pub_cfg = (N_primed, e)
#    priv_cfg = (nonce, ciphertext, tag)
#    
#    print("Set RSA modulus on server: ")
#    cr.restore_config(pub_cfg, priv_cfg)
#    
#    #get message and signed counterpart
#    
#    
#    return "BREAKPOINT NEW"
#    
#    
#    d = pohlig_hellman_algorithm_general(primes_to_use_final, exponents_final, N_primed, phi_of_N_primed, signature_in_integer, message_in_integer)
#    print("Secret key: ")
#    print(d)
#
#    pub_cfg = (N, e)
#    priv_cfg = (nonce, ciphertext, tag)
#    
#    #debugging
#    #restore_config(self, pub_cfg, priv_cfg):
#    
#    #set chosen N'
#    print("Set RSA modulus on server: ")
#    response = cr.restore_config(pub_cfg, priv_cfg)
#    
#    #factory reset
#    #server will use after this the initial rsa modulus but self.warranty_void = False, which is a condition we need to get the flag #see discussion above
#    print("Factory reset now:")
#    print(cr.factory_config())
#    #get flag
#    #get_flag(self, secret_d, rsa_modulus):
#    #note that we use the original server RSA modulus N
#    print("Get flag now: ")
#    print(cr.get_flag(d, N))
#    
#    
#    return "BREAKPOINT NEW"
    
    
    
    
    print("CarpetRemote init")
    cr = CarpetRemote(tn, carpet_key, carpet_cloud_key)
    
    #save_config causes the server to send is the public key parameters of self.skey                 [carpet_test_key] along with it the ciphertext containing the encrypted corresponding private key information, encrypted using a 16 random bytes sequence, used nonce, and the tag (also generated by AES, using self.config_key (the same 16 random byte sequence)
    
    #get data about key used by server
    # are interested all but N since we are going to change the RSA modulus on the server.
    print("save_config init")
    (N, e), (nonce, ciphertext, tag) = cr.save_config()
    #bit_length_of_N = len(long_to_bytes(N)) * 8 #1 byte as 8 bits
    
    
    #generate N' such that N' is prime and we know the factorization of N' - 1 = phi(N') (euler toitient)
    #N' should also be of 2048 bits, like the original RSA modulus
    #I imagine that the system of congruence quations we get (after Pohlig-Hellmann and have to apply CRT to) must contain enough information to solve for d. I think 2048 bits ro more should be sufficient.
    #In paper, mid sized primes factors should be of roughly 20 bits.
    #this gives us a pointer how big the prime factors of N' - 1 = phi(N') should be.
    
    
    print("generate_N_primed_ init")
    (primes_to_use_final, exponents_final, N_primed, phi_of_N_primed) = generate_N_primed_()
    #debugging purpose
    print("primes_to_use_final: ", end="")
    print(primes_to_use_final)
    print("exponents_final: ", end="")
    print(exponents_final)
    print("N_primed: ", end="")
    print(N_primed)
    print("phi_of_N_primed: ", end="")
    print(phi_of_N_primed)
    
    '''
    https://en.wikipedia.org/wiki/Smooth_number
    Smooth integer: A natural number k is n-smooth if all of its prime factors are <= n.
    '''
    #the computed phi_of_N_primed should be smooth enough for our purposes
    #it indeed is (tested)

    #N_primed is a prime (with high probability). This prime number should be big enough, and hopefully, p - 1 is sufficiently smooth to apply pohlig hellman algorithm
    
    pub_cfg = (N_primed, e)
    priv_cfg = (nonce, ciphertext, tag)
    
    #debugging
    #restore_config(self, pub_cfg, priv_cfg):
    
    #set chosen N'
    print("Set RSA modulus on server: ")
    cr.restore_config(pub_cfg, priv_cfg)
    #on server-side, we have the corresponding json.dumps(signed_message).encode() that is signed, not just "ok"
    
    #get error message with corresponding signature
    #'signed_error': 'ValueError:invalid signature', 'signature': [....]
    error_message = cr.get_status()
    message = error_message["signed_error"] #we get plaintext 'InvalidSignature:'
    signature = error_message["signature"] #and some signature
    
    #debugging
    print(message)
    print(signature)
    #return "breakpoiont"
    
    #note that we have to encode the message with the special encoding (defined somewhere at the beginning) because that's how this specific sign - verifiction scheme works.
    message_in_integer = bytes_to_long(encode(message.encode(), len(long_to_bytes(N_primed)))) 
    signature_in_integer = bytes_to_long(bytes.fromhex(signature))
    
    #s = m ^ d mod N'
    #debugging
#    print("signed_message: ", end="")
#    print(signature)
#    
#    print("message_in_integer: ", end="")
#    #print(json.dumps(signed_message).encode())
#    
#    print(message_in_integer)
#    
#    print("signature.hex(): ", end="")
#    print(signature)
#    
#    print("signature_as_int: ", end="")
#    print(signature_in_integer)
    
    #check if it's smaller.
    #check inequality debugging
    print("Check inequality")
    print(signature_in_integer <= phi_of_N_primed)
    print(message_in_integer <= phi_of_N_primed)
    
    
    #testing to check if CTF works
    #chinese_remainder_theorem(r_values_list, prime_power_list, phi_N_primed):
    #print(chinese_remainder_theorem([1,2,4], [3,4,5], 60)) #= 34 okay
    #print(chinese_remainder_theorem([1,2,3,5], [4,3,5,7], 420))
    #pohlig_hellman_algorithm(primes_to_use_final, exponents_final, N_primed, phi_of_N_primed, signature_in_integer, message_in_integer):   
    
    #debugging
    #3 = 11^x mod 29
    #print(baby_step_giant_step(3, 11, 29, 29)) #= 17
    #13 = 5 ^ x mod 37
    #print(baby_step_giant_step(13, 5, 37, 37)) #= 13
    #28 = 2^n mod 37
    #print(baby_step_giant_step(28, 2, 37, 37)) #= 34
    #print(baby_step_giant_step(3, 5, 23, 23)) #= 16
    
    #return "breakpoint"
    
    #phi_of_N_primed is smooth hopefully
    #apply Pohlig Hellman algorithm
    #https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm
    print("Performing pohlig_hellman_algorithm_general now:")
    #def pohlig_hellman_algorithm_general(list_of_primes, list_of_exponents, N_primed, phi_of_N_primed, sign_int, msg_int):
        
    d = pohlig_hellman_algorithm_general(primes_to_use_final, exponents_final, N_primed, phi_of_N_primed, signature_in_integer, message_in_integer)
    print("Secret key: ")
    print(d)

    pub_cfg = (N, e)
    priv_cfg = (nonce, ciphertext, tag)
    
    #debugging
    #restore_config(self, pub_cfg, priv_cfg):
    
    #debugging
    #print("Set RSA modulus on server: ")
    #response = cr.restore_config(pub_cfg, priv_cfg)
    
    #factory reset
    #server will use after this the initial rsa modulus but self.warranty_void = False, which is a condition we need to get the flag #see discussion above
    print("Factory reset now:")
    print(cr.factory_config())
    #get flag
    #get_flag(self, secret_d, rsa_modulus):
    #note that we use the original server RSA modulus N
    print("Get flag now: ")
    print(cr.get_flag(d, N))
    
    #print(cr.save_config())
    #print(cr.get_status())

if __name__ == "__main__":
    from public import carpet_pubkey, cloud_pubkey
    from public import carpet_test_key, cloud_test_key

    PORT = 51041

    if REMOTE:
        HOSTNAME = "aclabs.ethz.ch"
        key = carpet_pubkey
        cloud_key = cloud_pubkey
        #we are only given public keys

    else:
        HOSTNAME = "localhost"
        key = carpet_test_key
        cloud_key = cloud_test_key

    with Telnet(HOSTNAME, PORT) as tn:
        attack(tn, key, cloud_key)
