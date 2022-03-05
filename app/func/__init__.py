import zlib
import base45
import math
from cwt import COSEKey
import cbor_json
from cose.messages import Sign1Message
from cose.keys import CoseKey
from cose.headers import Algorithm, KID
from cose.algorithms import  Es256
from cose.keys.curves import  P256
from cose.keys.keyparam import KpKty,  KpKeyOps, EC2KpX, EC2KpY, EC2KpD, EC2KpCurve
from cose.keys.keytype import KtyEC2
from cose.keys.keyops import SignOp, VerifyOp


from ecdsa import SigningKey, VerifyingKey

class NeoCBOR:
    def __init__(self, payload_dict):
        #algorithm used
        self.payload = '01'
        #kid
        self.payload = self.payload + (1).to_bytes(2, byteorder='big').hex()
        #tag for number of bytes used by unix time integer
        hex_temp = (hex(payload_dict[4]))[2:]
        self.payload = self.payload + (len(hex_temp)//2).to_bytes(1, byteorder='big').hex()
        #unix date
        self.payload = self.payload + hex_temp
        #tag for number of bytes used by unix time integer
        hex_temp = (hex(payload_dict[6]))[2:]
        self.payload = self.payload + (len(hex_temp)//2).to_bytes(1, byteorder='big').hex()
        #unix date
        self.payload = self.payload + hex_temp
        #tag for bytes used by surname
        hex_temp = (payload_dict[-260][1]["nam"]["fn"]).encode('utf-8').hex()
        self.payload = self.payload + (len(hex_temp)//2).to_bytes(1, byteorder='big').hex()
        self.payload = self.payload + hex_temp
        #tag for bytes used by name
        hex_temp = (payload_dict[-260][1]["nam"]["gn"]).encode('utf-8').hex()
        self.payload = self.payload + (len(hex_temp)//2).to_bytes(1, byteorder='big').hex()
        self.payload = self.payload + hex_temp
        #tag for number of bytes used by unix time integer
        hex_temp = (hex(payload_dict[-260][1]["dob"]))[2:]
        self.payload = self.payload + (len(hex_temp)//2).to_bytes(1, byteorder='big').hex()
        self.payload = self.payload + hex_temp
        #type of certificate
        self.payload = self.payload + (1).to_bytes(1, byteorder='big').hex()
        if 1:
            #disease targeted & num
            self.payload = self.payload + (10).to_bytes(1, byteorder='big').hex()
            self.payload = self.payload + (200).to_bytes(1, byteorder='big').hex()
            #vaccine used
            self.payload = self.payload + (500).to_bytes(2, byteorder='big').hex()
            #doses done and expected
            self.payload = self.payload + (payload_dict[-260][1]["v"][0]["sd"]).to_bytes(1, byteorder='big').hex()
            self.payload = self.payload + (payload_dict[-260][1]["v"][0]["dn"]).to_bytes(1, byteorder='big').hex()
            #date of vaccine
            hex_temp = (hex(payload_dict[-260][1]["dob"]))[2:]
            self.payload = self.payload + (len(hex_temp)//2).to_bytes(1, byteorder='big').hex()
            self.payload = self.payload + hex_temp

    

def sign_newcose(payload_dict, qualcosa=0):
    with open("./app/certs/private.pem") as key_file:
        private_key = SigningKey.from_pem(key_file.read())

    with open("./app/certs/public.pem") as key_file:
        public_key = VerifyingKey.from_pem(key_file.read())

    neocbor = NeoCBOR(payload_dict)
    signature = private_key.sign(bytes.fromhex(neocbor.payload))
    try:
        print(public_key.verify(signature, bytes.fromhex(neocbor.payload)))
    except:
        print(False)
    full_payload = signature.hex() + neocbor.payload
    print(neocbor.payload)
    zlib_data = zlib.compress(bytes.fromhex(full_payload)) 
    base45_data = base45.b45encode(zlib_data)
    base45_data = base45_data.decode('utf-8')
    # print(len(base45_data))
    return base45_data


    

def sign_GP(payload_dict, kid_int):

    #payload of the DCC get passed to the 
    payload = cbor_json.cbor_from_native(payload_dict)
    kid = kid_int.to_bytes(2, 'big')
    
    with open("./app/certs/private.pem") as key_file:
        private_key = COSEKey.from_pem(key_file.read()) 
    # # print(vars(private_key))

    cose_key ={
        KpKty: KtyEC2, EC2KpCurve: P256, KpKeyOps: [SignOp, VerifyOp],
        EC2KpD: (private_key._d),
        EC2KpX: (private_key._x),
        EC2KpY: (private_key._y),
    }
    cose_key = CoseKey.from_dict(cose_key)

    msg = Sign1Message(phdr={Algorithm: Es256, KID: kid}, uhdr={}, payload=payload)
    msg.key=cose_key
    encoded=msg.encode()
    decoded = Sign1Message.decode(encoded)
    decoded.key = cose_key
    assert(decoded.verify_signature())

    cose_hex = bytes.fromhex(encoded.hex())
    # print(cose_hex.hex())
    zlib_data = zlib.compress(b'4BCB8A4680476BBECFB3C9D7B7E14402164E016E6D4D7CD8A221DBDA9205044F3654F9C17C2D4F03BDF24BA55755D374B381976439D7960406399A46D404A466') 
    # zlib_data = zlib.compress(cose_hex) 
    base45_data = base45.b45encode(zlib_data)
    base45_data = "HC1:"+base45_data.decode('utf-8')
    # print(len(base45_data))
    return base45_data