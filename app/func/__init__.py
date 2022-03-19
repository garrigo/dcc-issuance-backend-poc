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
import hashlib
from datetime import datetime
import json

import jks #https://pypi.org/project/pyjks/
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
import rsa
import base64

def add_storedKeys(store_path, psw):
    ks = jks.KeyStore.load(store_path, psw)
    keys = {}
    for alias, c in ks.certs.items():
        pk = ks.certs[alias]
        if not pk.is_decrypted():
            pk.decrypt(psw)
        cert = x509.load_der_x509_certificate(pk.cert)
        fingerprint = cert.fingerprint(hashes.SHA256()).hex() 
        serial_number = cert.serial_number 
        not_before = str(cert.not_valid_before) 
        not_after = str(cert.not_valid_after) 
        issuer = (str(cert.issuer))[6:-2] 
        subject = (str(cert.subject))[6:-2] 

        publicKeyPem = cert.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)[27:-26]
        keys[alias] = {"serialNumber": serial_number,
                        "subject": subject,
                        "issuer": issuer,
                        "notBefore":not_before,
                        "not_after":not_after,
                        "fingerprint":fingerprint,
                        "publicKeyPem":publicKeyPem.decode('utf-8')}
    return keys
def public_certs():
    keys = {}
    keys["ECDSA"] = add_storedKeys('./app/certs/publicKeyES.jks', 'public')
    keys["RSA"] = add_storedKeys('./app/certs/publicKeyRSA.jks', 'public')
    with open("app/static/json/certificates.json", "w") as f:
        json.dump(keys, f, indent=4)

# public_certs()

class NeoCBOR:
    def __init__(self, payload_dict, kid):
        #kid
        self.payload = (kid).to_bytes(2, byteorder='big').hex()
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
        if "v" in payload_dict[-260][1]:
            #vaccine certificate (v)
            self.payload = self.payload + (1).to_bytes(1, byteorder='big').hex()
            #disease targeted num (tg)
            self.payload = self.payload + (payload_dict[-260][1]["v"][0]["tg"]).to_bytes(2, byteorder='big').hex()
            #vaccine used (mp)
            self.payload = self.payload + (payload_dict[-260][1]["v"][0]["mp"]).to_bytes(2, byteorder='big').hex()
            #doses done and expected (dn - sd)
            self.payload = self.payload + (payload_dict[-260][1]["v"][0]["dn"]).to_bytes(1, byteorder='big').hex()
            self.payload = self.payload + (payload_dict[-260][1]["v"][0]["sd"]).to_bytes(1, byteorder='big').hex()
            #date of vaccine (dt)
            hex_temp = (hex(payload_dict[-260][1]["v"][0]["dt"]))[2:]
            self.payload = self.payload + (len(hex_temp)//2).to_bytes(1, byteorder='big').hex()
            self.payload = self.payload + hex_temp
        elif "t" in payload_dict[-260][1]:
            #test certificate (t)
            self.payload = self.payload + (2).to_bytes(1, byteorder='big').hex()
            #disease targeted num (tg)
            self.payload = self.payload + (payload_dict[-260][1]["t"][0]["tg"]).to_bytes(2, byteorder='big').hex()
            #test result (tr)
            self.payload = self.payload + (payload_dict[-260][1]["t"][0]["tr"]).to_bytes(1, byteorder='big').hex()
            #test used (ma)
            self.payload = self.payload + (payload_dict[-260][1]["t"][0]["ma"]).to_bytes(2, byteorder='big').hex()
            #date of test (sc)
            hex_temp = (hex(payload_dict[-260][1]["t"][0]["sc"]))[2:]
            self.payload = self.payload + (len(hex_temp)//2).to_bytes(1, byteorder='big').hex()
            self.payload = self.payload + hex_temp
        elif "r" in payload_dict[-260][1]:
            #recovery certificate
            self.payload = self.payload + (3).to_bytes(1, byteorder='big').hex()
            #disease targeted num (tg)
            self.payload = self.payload + (payload_dict[-260][1]["r"][0]["tg"]).to_bytes(2, byteorder='big').hex()
            #date of first positive test (fr)
            hex_temp = (hex(payload_dict[-260][1]["r"][0]["fr"]))[2:]
            self.payload = self.payload + (len(hex_temp)//2).to_bytes(1, byteorder='big').hex()
            self.payload = self.payload + hex_temp
            #date of beginning validity (df)
            hex_temp = (hex(payload_dict[-260][1]["r"][0]["df"]))[2:]
            self.payload = self.payload + (len(hex_temp)//2).to_bytes(1, byteorder='big').hex()
            self.payload = self.payload + hex_temp
            #date of ending validity (du)
            hex_temp = (hex(payload_dict[-260][1]["r"][0]["du"]))[2:]
            self.payload = self.payload + (len(hex_temp)//2).to_bytes(1, byteorder='big').hex()
            self.payload = self.payload + hex_temp
        self.payload = bytes.fromhex(self.payload)


# Decode DCC
def decode_newcose(payload):
    # from string to bytes -> decode base45 -> decompress with zlib
    payload = payload.encode('utf-8')
    payload = base45.b45decode(payload)
    payload = zlib.decompress(payload)
    with open('./app/static/json/algorithm.json') as f:
        signature_gap = (json.load(f))["valueSetValues"][str(payload[0])]["signatureBytes"] + 1
    start = signature_gap + 2 #67
    byte_counter = payload[start] #4
    start +=1 #68
    end_cert = int.from_bytes(payload[start:start+byte_counter], "big")
    start += byte_counter
    byte_counter = payload[start]
    start +=1
    begin_cert = int.from_bytes(payload[start:start+byte_counter], "big")
    start += byte_counter
    byte_counter = payload[start]
    start +=1
    surname = payload[start:start+byte_counter].decode('utf-8')
    start += byte_counter
    byte_counter = payload[start]
    start +=1
    name = payload[start:start+byte_counter].decode('utf-8')
    start += byte_counter
    byte_counter = payload[start] #4
    start +=1 #68
    birth = int.from_bytes(payload[start:start+byte_counter], "big")
    start += byte_counter
    cert_type = payload[start]
    start +=1 
    disease = int.from_bytes(payload[start:start+2], "big")
    start +=2
    with open('./app/static/json/disease-agent-targeted.json') as f:
        disease = (json.load(f))["valueSetValues"][str(disease)]["display"]
    if cert_type==1:
        vaccine = int.from_bytes(payload[start:start+2], "big")
        with open('./app/static/json/vaccine-medicinal-product.json') as f:
            vaccine = (json.load(f))["valueSetValues"][str(vaccine)]["display"]
        start +=2
        doses_done = payload[start]            
        start +=1
        doses_req = payload[start]
        start +=1
        byte_counter = payload[start]
        start +=1
        date_vax = int.from_bytes(payload[start:start+byte_counter], "big")
        
        dcc = {
            "Begin_certificate": datetime.utcfromtimestamp(begin_cert).strftime('%Y-%m-%d %H:%M'), 
            "End_certificate": datetime.utcfromtimestamp(end_cert).strftime('%Y-%m-%d %H:%M'),
            "Surname": surname,
            "Name": name,
            "Date of birth": datetime.utcfromtimestamp(birth).strftime('%Y-%m-%d'),
            "Disease Targeted": disease,
            "Vaccine used": vaccine,
            "Doses done": doses_done,
            "Doses requested": doses_req,
            "Date of vaccination": datetime.utcfromtimestamp(date_vax).strftime('%Y-%m-%d %H:%M'),
        }
    elif cert_type==2:
        result = payload[start]
        start +=1
        test = int.from_bytes(payload[start:start+2], "big")
        with open('./app/static/json/test-used.json') as f:
            test = (json.load(f))["valueSetValues"][str(test)]["display"]
        start +=2
        byte_counter = payload[start]
        start +=1
        date_test = int.from_bytes(payload[start:start+byte_counter], "big")
        dcc = {
            "Begin_certificate": datetime.utcfromtimestamp(begin_cert).strftime('%Y-%m-%d %H:%M'), 
            "End_certificate": datetime.utcfromtimestamp(end_cert).strftime('%Y-%m-%d %H:%M'),
            "Surname": surname,
            "Name": name,
            "Date of birth": datetime.utcfromtimestamp(birth).strftime('%Y-%m-%d'),
            "Disease Targeted": disease,
            "Result": "Detected" if result else "Not detected",
            "Test used": test,
            "Date of test": datetime.utcfromtimestamp(date_test).strftime('%Y-%m-%d %H:%M'),
        }
    elif cert_type==3:
        byte_counter = payload[start]
        start +=1
        date_fr = int.from_bytes(payload[start:start+byte_counter], "big")
        start += byte_counter
        byte_counter = payload[start]
        start +=1
        date_df = int.from_bytes(payload[start:start+byte_counter], "big")
        start += byte_counter
        byte_counter = payload[start]
        start +=1
        date_du = int.from_bytes(payload[start:start+byte_counter], "big")  
        dcc = {
            "Begin_certificate": datetime.utcfromtimestamp(begin_cert).strftime('%Y-%m-%d %H:%M'), 
            "End_certificate": datetime.utcfromtimestamp(end_cert).strftime('%Y-%m-%d %H:%M'),
            "Surname": surname,
            "Name": name,
            "Date of birth": datetime.utcfromtimestamp(birth).strftime('%Y-%m-%d'),
            "Disease Targeted": disease,
            "Date of first positive test": datetime.utcfromtimestamp(date_fr).strftime('%Y-%m-%d %H:%M'),
            "Date of beginning of validity": datetime.utcfromtimestamp(date_df).strftime('%Y-%m-%d %H:%M'),
            "Date of ending of validity": datetime.utcfromtimestamp(date_du).strftime('%Y-%m-%d %H:%M'),
        }
    print(dcc)                   
    

# Verify DCC signature against payload
def verify_newcose(payload):
    # from string to bytes -> decode base45 -> decompress with zlib
    payload = payload.encode('utf-8')
    payload = base45.b45decode(payload)
    # payload = zlib.decompress(payload)
    #extract algorithm id and check length of signature
    algo = payload[0]
    with open('./app/static/json/algorithm.json') as f:
        signature_gap = (json.load(f))["valueSetValues"][str(algo)]["signatureBytes"] + 1
    #extract signature and payload and verify the former against the latter
    signature = payload[1:signature_gap]
    payload = payload[signature_gap:]
    kid = str(int.from_bytes(payload[0:2], "big"))
    #open public key store
    if algo == 0:
        algo_name = "ECDSA"
        # ks = jks.KeyStore.load('./app/certs/publicKeyES.jks', 'public')
    elif algo == 1:
        algo_name = "RSA"
        # ks = jks.KeyStore.load('./app/certs/publicKeyRSA.jks', 'public')

    # pk = ks.certs[kid]
    # if not pk.is_decrypted():
    #     pk.decrypt('public')

    # pk_der = x509.load_der_x509_certificate(pk.cert).public_key().public_bytes(encoding=serialization.Encoding.DER,
    #         format=serialization.PublicFormat.SubjectPublicKeyInfo)
    if algo == 0:
        #open public key
        with open('./app/static/json/certificates.json') as f:
            public_key = VerifyingKey.from_pem((json.load(f))[algo_name][kid]["publicKeyPem"])
        # public_key = VerifyingKey.from_der(pk_der)
        assert(public_key.verify(signature, payload,  hashfunc=hashlib.sha256))
    elif algo == 1:
        #open public key
        pass

def sign_newcose(payload_dict, algo=0, kid=2):
    try:
        #open private key store
        if (algo == 0):
            ks = jks.KeyStore.load('./app/certs/privateKeyES.jks', 'private')
        else:
            ks = jks.KeyStore.load('./app/certs/privateKeyRSA.jks', 'private')
        pk = ks.private_keys[str(kid)]
        
        if not pk.is_decrypted():
            pk.decrypt('private')
        if pk.algorithm_oid == jks.util.RSA_ENCRYPTION_OID:
            pk_der = pk.pkey
        else:
            pk_der = pk.pkey_pkcs8

        #create neocbor structure
        neocbor = NeoCBOR(payload_dict, kid)  
        #sign neocbor bytes
        if algo == 0: 
            private_key = SigningKey.from_der(pk_der)
            signature = private_key.sign(neocbor.payload, hashfunc=hashlib.sha256)
        else:
            private_key = rsa.PrivateKey.load_pkcs1(pk_der, 'DER')
            signature = rsa.sign(neocbor.payload, private_key, 'SHA-256')
            
        #algorithm used
        algo = algo.to_bytes(1, byteorder='big')   
        #concatenate algorithm id, signature and payload bytes
        full_payload = algo + signature + neocbor.payload
        # print(len(full_payload))
        print("Uncompressed: "+str(len(full_payload)))
        #compress full payload with zlib -> encode in base45 -> from bytes to string for the qr code creation
        zlib_data = zlib.compress(full_payload)
        print("Compressed: "+str(len(zlib_data)))
        base45_data = base45.b45encode(zlib_data)
        base45_data2 = base45.b45encode(full_payload)
        base32_data = base64.b32encode(full_payload)
        base64_data = base64.b64encode(full_payload)
        

        # print(base45_data)
        
        iso_8859_1 = full_payload.decode('iso-8859-1')
        base45_data = base45_data.decode('utf-8')
        base45_data2 = base45_data2.decode('utf-8')
        base32_data = base32_data.decode('utf-8')
        base64_data = base64_data.decode('utf-8')
        print("Uncompressed base45: "+str(len(base45_data2)))
        print("Uncompressed iso_8859_1: "+str(len(iso_8859_1)))
        print("Compressed base45: "+str(len(base45_data)))
        print(base45_data2)
        print(base32_data)
        print(base64_data)
        #check if generated signature is correct
        verify_newcose(base45_data2)

        # decode_newcose(base45_data)
        return base45_data2
        return full_payload.hex()
    except Exception as e:
        print("ERROR at Sign: " + str(e))
        return False
    
    





def sign_GP(payload_dict, kid_int):

    #payload of the DCC get passed to the 
    payload = cbor_json.cbor_from_native(payload_dict)
    kid = kid_int.to_bytes(2, 'big')
    
    with open("./app/certs/private.pem") as key_file:
        private_key = COSEKey.from_pem(key_file.read()) 
    # print(vars(private_key))

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
    zlib_data = zlib.compress(cose_hex) 
    base45_data = base45.b45encode(zlib_data)
    base45_data = "HC1:"+base45_data.decode('utf-8')
    # print(len(base45_data))
    return base45_data