## using pyasn1

from pyasn1.type import univ
from pyasn1.codec.der.encoder import encode
from pyasn1.codec.der.decoder import decode
import binascii

encode(univ.Integer(1)).hex()
encode(univ.Real(0.0)).hex()

print("Decoded Integer:", decode(binascii.unhexlify('020100'), asn1Spec=univ.Integer()))
print("Decoded REAL:", decode(binascii.unhexlify('0900'), asn1Spec=univ.Real()))
