import zlib
import base45
import qrcode
from cwt import COSE, COSEKey
import cbor_json




def sign_GP(payload_dict, kid_int):

    payload = cbor_json.cbor_from_native(payload_dict)
    kid = kid_int.to_bytes(2, 'big')
    
    with open("./private.pem") as key_file:
        private_key = COSEKey.from_pem(key_file.read(), kid=kid)
    

    with open("./public.pem") as key_file:
        public_key = COSEKey.from_pem(key_file.read(), kid=kid)
    ctx = COSE.new()
    encoded = ctx.encode_and_sign(
        payload,
        private_key,
        protected={1: -7, 4: kid},
        unprotected={}
    )
    #Check signature 
    assert (payload == ctx.decode(encoded, public_key))

    cose_hex = bytes.fromhex(encoded.hex())
    print(cose_hex.hex())
    zlib_data = zlib.compress(cose_hex) 
    base45_data = base45.b45encode(zlib_data)
    base45_data = "HC1:".encode()+base45_data

    return base45_data