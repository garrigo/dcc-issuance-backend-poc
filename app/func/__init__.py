#from typing import final
# import pyzbar.pyzbar as pyzbar
import zlib
import base45
# import codecs
import qrcode

from binascii import unhexlify
from cose.messages import  Sign1Message
from PIL import Image
from binascii import unhexlify
from cose.messages import Sign1Message
from cose.keys import CoseKey

from cose.keys.curves import  P256
from cose.keys.keyparam import KpKty, KpKeyOps
from cose.keys.keyparam import EC2KpX, EC2KpY, EC2KpD, EC2KpCurve
from cose.keys.keytype import KtyEC2
from cose.keys.keyops import SignOp, VerifyOp


def tamperGP():
    return True


def sign_GP(hex_string):
    cose_data = bytes.fromhex(hex_string)
    cose_msg = Sign1Message.decode(cose_data)
    cose_key ={
        KpKty: KtyEC2, EC2KpCurve: P256, KpKeyOps: [SignOp, VerifyOp],
        EC2KpD: unhexlify(b'C477F9F65C22CCE20657FAA5B2D1D8122336F851A508A1ED04E479C34985BF96'),
        EC2KpX: unhexlify(b'B7E08AFDFE94BAD3F1DC8C734798BA1C62B3A0AD1E9EA2A38201CD0889BC7A19'),
        EC2KpY: unhexlify(b'3603F747959DBF7A4BB226E41928729063ADC7AE43529E61B563BBC606CC5E09'),
    }
    cose_key = CoseKey.from_dict(cose_key)
    neo_msg = Sign1Message(phdr = cose_msg.phdr, uhdr=cose_msg.uhdr, payload=cose_msg.payload)
    neo_msg.key = cose_key
    encoded = Sign1Message.encode(neo_msg)
    zlib_data = zlib.compress(encoded) 
    base45_data = base45.b45encode(zlib_data)

    return base45_data

# def verify_signature(qr_image):
#     qrDecoded = pyzbar.decode(qr_image)[0].data
    
#     # remove HC1
#     base45data = codecs.decode(qrDecoded, 'UTF-8').replace("HC1:","")
#     #decode from base45
#     zlibdata = base45.b45decode(base45data)
#     #decompress zlib
#     cose_data = zlib.decompress(zlibdata)

#     cose_key ={
#         KpKty: KtyEC2, EC2KpCurve: P256, KpKeyOps: [SignOp, VerifyOp],
#         EC2KpD: unhexlify(b'C477F9F65C22CCE20657FAA5B2D1D8122336F851A508A1ED04E479C34985BF96'),
#         EC2KpX: unhexlify(b'B7E08AFDFE94BAD3F1DC8C734798BA1C62B3A0AD1E9EA2A38201CD0889BC7A19'),
#         EC2KpY: unhexlify(b'3603F747959DBF7A4BB226E41928729063ADC7AE43529E61B563BBC606CC5E09'),
#     }
#     cose_key = CoseKey.from_dict(cose_key)

#     cose_msg = Sign1Message.decode(cose_data)
#     cose_msg.key = cose_key
#     return cose_msg.verify_signature()

# Produces a new QR code from b45 data
def qrBuildJPG(base45data):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    base45data = "HC1:".encode()+base45data
    qr.add_data(base45data)
    qr.make(fit=True) #qrcode.make(base45data)
    img = qr.make_image(fill='black', back_color='white')
    img.save("qr_generated.jpg")
    print("New QR has been generated.")