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

payload = "6BFOXN%TS3DHC S+/C6Y5J:74H95NL-AH+UCIOOA%I+645DO7/IQKVUD7IT4V22F/8X*G3M9JUPY0BX/KS96R/S09T./0LWTKD33238J3HKB5S4VV2 73-E3GG396B-43O058YIZ734234LTX63FG30$499TPU1PK9CZL9L6G%UBB6OMEU56JPEO*E$T6%P65UTF8EUM6%QE$QE$96H07RW6RA632N7PPDFPVX1R270:6NEQ.P6CG3GDB+6TYIJGDBQMI%ZIKCIGOJ0UIM42PBJBKB/MJZ JFYJ4OIMEDTJCDID$%MQQ5L/5R3FOKEH-BDNJE8A99LE4GUHBCZI:ZJ83BB9UUPT+.TJZTLZI1.0O*47*KB*KYQTKWTNS4.$S6ZC0JBDQJDG3ZQTNIBX87LD7S9WBSCHX7QKVQWP6XMAW4*36%:KG3N:7UI6SKZ6A:4ZUL YV*MU2TH2G4L4D +T96T9RQ.OHPTBS*9C4W+MPF.6:PE/WN.-E0003:NF.E"
payload = payload.encode('utf-8')
payload = base45.b45decode(payload)
payload = zlib.decompress(payload)
# print(payload.hex())

msg = {
    18: [
        {
            4: "CEB332B4",
            1: -7
        },
        {},
        {
            4: 1683849600,
            6: 1627989097,
            1: "IT",
            -260: {
                1: {
                    "v": [
                        {
                            "dn": 2,
                            "ma": "ORG-100030215",
                            "vp": "1119349007",
                            "dt": "2021-08-02",
                            "co": "IT",
                            "ci": "01IT4F66CD2D369244C6AE064233599F2C0E#4",
                            "mp": "EU/1/20/1528",
                            "is": "Ministero della Salute",
                            "sd": 2,
                            "tg": "840539006"
                        }
                    ],
                    "nam": {
                        "fnt": "ARRIGO",
                        "fn": "ARRIGO",
                        "gnt": "GIACOMO",
                        "gn": "GIACOMO"
                    },
                    "ver": "1.0.0",
                    "dob": "1995-05-18"
                }
            }
        }
    ]
}


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

def encodeDCC(payload):
    dcc = b''
    with open("app/static/json/dccBlueprint.json", "r") as f:
              
        schema = (json.load(f))["schema"]
        blueprint = schema[0]["shared"] + schema[1]["exclusive"][str(payload["cert_type"])]
        
        for block in blueprint:  
            if block["type"] == "int":
                num = (payload[block["id"] ]).to_bytes(block["bytes"], byteorder='big')
                dcc = dcc + num
            elif block["type"] == "string":
                temp = bytes(payload[block["id"] ], 'utf-8')
                dcc = dcc + (len(temp)).to_bytes(block["bytes"], byteorder='big')
                dcc = dcc + temp 
            elif block["type"] == "date":
                hex_temp = (hex(payload[block["id"] ]))[2:]
                dcc = dcc + (len(hex_temp)//2).to_bytes(block["bytes"], byteorder='big')
                dcc = dcc + bytes.fromhex(hex_temp)
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
        payload_dict["algorithm"] = algo
        payload_dict["kid"] = kid
        #create dcc payload
        dcc_payload = encodeDCC(payload_dict)  
        #sign dcc_payload bytes
        if algo == 0: 
            private_key = SigningKey.from_der(pk_der)
            signature = private_key.sign(dcc_payload, hashfunc=hashlib.sha256)
        else:
            private_key = rsa.PrivateKey.load_pkcs1(pk_der, 'DER')
            signature = rsa.sign(dcc_payload, private_key, 'SHA-256')
        #concatenate payload and signature bytes
        dcc = dcc_payload + signature 
        
        # print("Uncompressed: "+str(len(dcc)))
        #compress full payload with zlib -> encode in base45 -> from bytes to string for the qr code creation
        zlib_data = zlib.compress(dcc)
        # print("Compressed: "+str(len(zlib_data)))
        base45_data = base45.b45encode(zlib_data)
        base45_data2 = base45.b45encode(dcc)
        base32_data = base64.b32encode(dcc)
        base64_data = base64.b64encode(dcc)
        
        
        # print(base45_data)
        
        iso_8859_1 = dcc.decode('iso-8859-1')
        base45_data = base45_data.decode('utf-8')
        base45_data2 = base45_data2.decode('utf-8')
        base32_data = base32_data.decode('utf-8')
        base64_data = base64_data.decode('utf-8')
        # print("Uncompressed base45: "+str(len(base45_data2)))
        # print("Uncompressed iso_8859_1: "+str(len(iso_8859_1)))
        # print("Compressed base45: "+str(len(base45_data)))
        # print(base45_data2)
        # print(base32_data)
        # print(base64_data)
        #check if generated signature is correct
        verify_newcose(base45_data2)

        # decode_newcose(base45_data)
        return base45_data2
        return dcc.hex()
    except Exception as e:
        print("ERROR at Sign: " + str(e))
        return False
    


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
    print(len(encoded))
    cose_hex = bytes.fromhex(encoded.hex())
    print(cose_hex.hex())
    zlib_data = zlib.compress(cose_hex) 
    base45_data = base45.b45encode(zlib_data)
    base45_data = "HC1:"+base45_data.decode('utf-8')
    print(len(base45_data))
    return base45_data