import json
from typing import Optional
from telnetlib import Telnet

from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.PublicKey.ECC import EccKey
from Crypto.Signature import DSS

# IMPORTANT: Change this to False if you want to run the client against your local implementation
REMOTE = True

class CarpetRemote():
    def __init__(self, tn: Telnet, carpet_key: EccKey, cloud_key: EccKey):
        self.tn = tn
        self.carpet_key = carpet_key
        self.cloud_key = cloud_key
        self.identity = "carpet_cloud"

    def json_recv(self):
        line = self.tn.read_until(b"\n")
        return json.loads(line.decode())

    def json_send(self, req: dict):
        request = json.dumps(req).encode()
        self.tn.write(request + b"\n")

    def json_signed_send(self, req: dict):
        req_hash = SHA256.new(json.dumps(req).encode()) #json dictionary, command, encoded
        # Your code here.
        '''
        Idea: We know that the server receives my message, checks the validity for the accompanying signature, then sends back a message and its signature.
        So we know that the server code has everything we need for the implementation task and we can just copy and paste, with small modifications (and taking into account which key we have to use to sign/verify signature).
        '''
        
        '''
        Relevant snipped: copy pasted from server code - for convienence.
        server code for signing - copied into this file.
        res_hash = SHA256.new(json.dumps(response).encode())
        signature = DSS.new(self.key, 'fips-186-3').sign(res_hash)
        return {"signed_res": response, "signature": signature.hex()}
        '''
        
        '''
        By description of task, namely "Every command will need to be signed by the Carpet Cloud, and every response will be signed by the Carpet.", we can infer what key we need to use to sign the command to send, namely self.cloud_key.
        '''
        signature = DSS.new(self.cloud_key, 'fips-186-3').sign(req_hash)
        '''
        self.identity is here "carpet_cloud"; based on server code, the server uses the public key for the identity carpet_cloud to check the signature. so we have to use the corresponding private key self.cloud_key to sign the message we want to send to the server.
        '''
        
        self.json_send({
            "identity": self.identity, 
            "msg": req,
            "signature": signature.hex()
        })

    def json_signed_recv(self):
        res = self.json_recv()
        signature = bytes.fromhex(res["signature"])

        if "signed_res" in res:
            signed = json.dumps(res["signed_res"]).encode()
        else:
            signed = res["signed_error"].encode()

        h = SHA256.new(signed)
        
        '''
        Idea: We know that the server receives my message, checks the validity for the accompanying signature, then sends back a message and its signature.
        So we know that the server code has everything we need and we can just copy and paste, with small modifications (and taking into account which key we have to use to sign/verify signature).
        '''
        
        '''
        Relevant snipped: copy pasted from server code - for convienence.
        server code verification code - copied into this file.
        msg = signed_msg["msg"]
        signature = bytes.fromhex(signed_msg["signature"])
        # Pick the verification key depending on the sender
        identity = signed_msg["identity"]
        signer_key = self.trusted_entities[identity]

        h = SHA256.new(json.dumps(msg).encode())
        verifier = DSS.new(signer_key, 'fips-186-3')
        try:
            verifier.verify(h, signature)

            response = self.exec_command(msg)
            res_hash = SHA256.new(json.dumps(response).encode())
            signature = DSS.new(self.key, 'fips-186-3').sign(res_hash)
            return {"signed_res": response, "signature": signature.hex()}
        except ValueError as e:
            error_text = time.ctime() + ": error: " + type(e).__name__ + ": " + str(e)
            err_hash = SHA256.new(error_text.encode())
            signature = DSS.new(self.key, 'fips-186-3').sign(err_hash)
            return {"signed_error": error_text, "signature": signature.hex()}
        '''
        
        '''
        By description of task, namely "Every command will need to be signed by the Carpet Cloud, and every response will be signed by the Carpet.", we can infer what key we need to use to verify the received command, namely self.carpet_key.
        '''
        # Your code here.
        #This code snipped for verifying is basically an abdriged version of the server code for the verification of commands received.
        '''
        based on server code, the server uses the private key given by the identity "carpet" (in server code, this corresponds to the key denoted as "self.key"), which is the carpet_key, to sign the messages it sends to us, the client. So to verify, I use the corresponding public key, namely self.carpet_key.
        '''
        verifier = DSS.new(self.carpet_key, 'fips-186-3')
        try:
            verifier.verify(h, signature)
            return signed
        except ValueError as e:
            error_text = ": error: " + type(e).__name__ + ": " + str(e)
            return error_text

        #return signed
        
    def get_flag(self):
        #note that this method is very similiar to the method get_status; it just has another command, the command "backdoor" to get the flag. Basically, if get_status works, then get_flag should also work.
        obj = {
            "command": "backdoor"
        }
        self.json_signed_send(obj)
        res = self.json_signed_recv()
        return res

    def get_status(self):
        obj = {
            "command": "get_status"
        }
        self.json_signed_send(obj)
        res = self.json_signed_recv()
        return res

def interact(tn: Telnet, carpet_key: EccKey, carpet_cloud_key: Optional[EccKey]):
    """ Get the flag here.
    """
    cr = CarpetRemote(tn, carpet_key, carpet_cloud_key)

    #not needed.
    #print(cr.get_status())
    
    #used defined method to get the flag
    print(cr.get_flag())

if __name__ == "__main__":
    from public import carpet_pubkey, cloud_key
    from public import carpet_test_key, cloud_test_key

    PORT = 51030

    if REMOTE:
        HOSTNAME = "aclabs.ethz.ch"
        key = carpet_pubkey
        cloud_key = cloud_key

    else:
        HOSTNAME = "localhost"
        key = carpet_test_key
        cloud_key = cloud_test_key

    with Telnet(HOSTNAME, PORT) as tn:
        interact(tn, key, cloud_key)
