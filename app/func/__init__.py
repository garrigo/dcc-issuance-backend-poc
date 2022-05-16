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
from app.func import dcc_pb2


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

def encode (payload, schema):
    byteString = b''
    for block in schema:  
        if block["type"] == "int":
            num = (payload[block["id"] ]).to_bytes(block["bytes"], byteorder='big')
            byteString = byteString + num
        elif block["type"] == "string":
            temp = bytes(payload[block["id"] ], 'utf-8')
            byteString = byteString + (len(temp)).to_bytes(block["bytes"], byteorder='big')
            byteString = byteString + temp 
        elif block["type"] == "date":
            hex_temp = (hex(payload[block["id"] ]))[2:]
            byteString = byteString + (len(hex_temp)//2).to_bytes(block["bytes"], byteorder='big')
            byteString = byteString + bytes.fromhex(hex_temp)
        elif block["type"] == "switch":
            if str(payload[block["id"]]) in block["cases"]:
                byteString = byteString + encode(payload, block["cases"][str(payload[block["id"]])])
            else:
                raise Exception("Certificate type not recognized.")
    return byteString

def encodeDCC(payload):
    dcc = b''
    with open("app/static/json/dccBlueprint.json", "r") as f:
        schema = (json.load(f))["schema"]
        dcc = encode(payload, schema)
    return dcc


def encodeDCCProtoBuffer(payload):
    dcc = dcc_pb2.DCC()
    dcc.version = payload['version']
    dcc.algorithm = payload['algorithm']
    dcc.kid = payload['kid']
    dcc.not_before = payload['not_before']
    dcc.not_after = payload['not_after']
    dcc.iss = payload['iss']
    dcc.name = payload['name']
    dcc.surname = payload['surname']
    dcc.date_of_birth = payload['date_of_birth']
    dcc.disease = payload['disease']
    # dcc.cert_type = payload['cert_type']
    if payload['cert_type'] == 1:
        dcc.v.vaccine = payload['vaccine']
        dcc.v.doses_done = payload['doses_done']
        dcc.v.doses_required = payload['doses_required']
        dcc.v.date_vaccine = payload['date_vaccine']
    elif payload['cert_type'] == 2:
        dcc.t.test_result = payload['test_result']
        dcc.t.test_used = payload['test_used']
        dcc.t.date_test = payload['date_test']
    elif payload['cert_type'] == 3:
        dcc.r.date_test = payload['date_test']
        dcc.r.date_from = payload['date_from']
        dcc.r.date_until = payload['date_until']
    else:
        raise Exception("Certificate type not recognized.")
    return dcc

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
        signature_length = (json.load(f))["valueSetValues"][str(algo)]["signatureBytes"]
    #extract signature and payload and verify the former against the latter
    signature = payload[-signature_length:]
    payload = payload[0:-signature_length]
    kid = str(int.from_bytes(payload[1:3], "big"))
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

def sign_dcc(payload_dict, algo=0, kid=2, version="1.3.0"):
    # try:
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
        payload_dict["algorithm"] = algo
        payload_dict["kid"] = kid
        payload_dict["version"] = version
        payload_dict["iss"] = "IT"
        # print(payload_dict)
        #serialize dcc payload using experimental data format
        dcc_payload = encodeDCC(payload_dict)  
        # print("Experimental length: ",len(dcc_payload))

        #serialize dcc payload using Protocol Buffers
        # proto_dcc = encodeDCCProtoBuffer(payload_dict)
        # dcc_payload = proto_dcc.SerializeToString()
        # print("Protobuf length: ",len(dcc_payload))
        

        #sign dcc_payload bytes
        if algo == 0: 
            private_key = SigningKey.from_der(pk_der)
            signature = private_key.sign(dcc_payload, hashfunc=hashlib.sha256)
        else:
            private_key = rsa.PrivateKey.load_pkcs1(pk_der, 'DER')
            signature = rsa.sign(dcc_payload, private_key, 'SHA-256')
        #concatenate payload and signature bytes
        dcc = dcc_payload + signature 
        # print(dcc.hex())
        # proto_dcc.signature = signature
        # proto_dcc = proto_dcc.SerializeToString()
        # print("Byte length: ",len(proto_dcc))
        # print(proto_dcc.hex())
        #compress full payload with zlib -> encode in base45 -> from bytes to string for the qr code creation
        # zlib_data = zlib.compress(dcc)
        
        base45_data = base45.b45encode(dcc)
        base32_data = base64.b32encode(dcc)
        base64_data = base64.b64encode(dcc)
        
        
        # print(base45_data)
        
        iso_8859_1 = dcc.decode('iso-8859-1')
        base45_data = base45_data.decode('utf-8')
        base32_data = base32_data.decode('utf-8')
        base64_data = base64_data.decode('utf-8')
        # print("Uncompressed base45: "+str(len(base45_data2)))
        # print("Uncompressed iso_8859_1: "+str(len(iso_8859_1)))
        # print("Compressed base45: "+str(len(base45_data)))
        # print(base45_data)
        # print(base32_data)
        # print(base64_data)
        #check if generated signature is correct
        # verify_newcose(base45_data2)

        # decode_newcose(base45_data)
        return base45_data
        return dcc.hex()
    # except Exception as e:
    #     print("ERROR at Sign: " + str(e))
    #     return False
    


def sign_GP(payload_dict, kid_int=1, algo=0):

    #payload of the DCC get passed to the 
    payload = cbor_json.cbor_from_native(payload_dict)
    kid = kid_int.to_bytes(2, 'big')
            #open private key store
    # if (algo == 0):
    #     ks = jks.KeyStore.load('./app/certs/privateKeyES.jks', 'private')
    # else:
    #     ks = jks.KeyStore.load('./app/certs/privateKeyRSA.jks', 'private')
    # pk = ks.private_keys[str(kid_int)]
    
    # if not pk.is_decrypted():
    #     pk.decrypt('private')
    # if pk.algorithm_oid == jks.util.RSA_ENCRYPTION_OID:
    #     pk_der = pk.pkey
    # else:
    #     pk_der = pk.pkey_pkcs8
    with open("./app/certs/private.pem") as key_file:
        private_key = COSEKey.from_pem(key_file.read()) 

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
    # print((encoded))
    # print(len(encoded))
    cose_hex = bytes.fromhex(encoded.hex())
    # print(cose_hex.hex())
    zlib_data = zlib.compress(cose_hex) 
    base45_data = base45.b45encode(zlib_data)
    base45_data = "HC1:"+base45_data.decode('utf-8')
    # print((base45_data))
    # print(len(base45_data))
    return base45_data