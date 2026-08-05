#### TODO

- [ ] ASN.1 Runtime
- [ ] ASN.1 Compiler
- [ ] ASN.1 Schema Loader
- [ ] ASN.1 Repository

#### references

* [ASN.1 JavaScript decoder](https://lapo.it/asn1js/)
* [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php)

#### YAML schema

* DER YAML schema

````
testvector:
  - example: string          # [mandatory] testcase
    schema: DER              # [mandatory] "DER"
    items:
      - item: string         # [mandatory]
        der: hexstring       # [mandatory]
````

#### using pyasn1

from pyasn1.type import univ
from pyasn1.codec.der.encoder import encode
from pyasn1.codec.der.decoder import decode
import binascii

encode(univ.Integer(1)).hex()
encode(univ.Real(0.0)).hex()

print("Decoded Integer:", decode(binascii.unhexlify('020100'), asn1Spec=univ.Integer()))
print("Decoded REAL:", decode(binascii.unhexlify('0900'), asn1Spec=univ.Real()))

#### ASN.1 DER

- RFC 2459 Internet X.509 Public Key Infrastructure Certificate and CRL Profile
- RFC 3039 Internet X.509 Public Key Infrastructure Qualified Certificates Profile
- RFC 3280 Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile
- RFC 5280 Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile
- RFC 5912 New ASN.1 Modules for the Public Key Infrastructure Using X.509 (PKIX)

DER
````
3082 0287 3082 020d a003 0201 0202 1454
62ff be6d 4b20 ec20 483b 13c7 736a d5ad
afae 9630 0a06 082a 8648 ce3d 0403 0230
5931 0b30 0906 0355 0406 1302 4b52 310b
3009 0603 5504 080c 024b 4e31 0b30 0906
0355 0407 0c02 474a 310d 300b 0603 5504
0a0c 0454 6573 7431 0d30 0b06 0355 040b
0c04 5465 7374 3112 3010 0603 5504 030c
0954 6573 7420 526f 6f74 301e 170d 3236
3035 3133 3232 3230 3032 5a17 0d32 3730
3531 3332 3232 3030 325a 3058 310b 3009
0603 5504 0613 024b 5231 0b30 0906 0355
0408 0c02 4b4e 310b 3009 0603 5504 070c
0247 4a31 0d30 0b06 0355 040a 0c04 5465
7374 310d 300b 0603 5504 0b0c 0454 6573
7431 1130 0f06 0355 0403 0c08 7465 7374
2e63 6f6d 3076 3010 0607 2a86 48ce 3d02
0106 052b 8104 0022 0362 0004 b27f 4ac8
e326 6939 f428 1dd9 02d4 274a 4009 74f4
7a29 e48b 3664 2e67 3398 0c59 06e4 fbce
12b6 4e87 7af0 66b2 4edb c6d7 192c be21
74f8 fa9f cb4d 8f7b 0772 5950 a11e a460
d127 b616 7106 1fe1 e17a a7cd 0047 d9b8
3ad0 edb7 c275 5e1d 151e cc5b a381 9630
8193 3009 0603 551d 1304 0230 0030 0b06
0355 1d0f 0404 0302 0780 3013 0603 551d
2504 0c30 0a06 082b 0601 0505 0703 0130
2406 0355 1d11 041d 301b 8208 7465 7374
2e63 6f6d 8209 6c6f 6361 6c68 6f73 7487
047f 0000 0130 1d06 0355 1d0e 0416 0414
f06a 5451 f417 33fc 377f 66b1 94d7 c56a
78e2 f032 301f 0603 551d 2304 1830 1680
146c b3f5 87bf 38ee dfdc 8697 57c6 9169
ea01 2313 4e30 0a06 082a 8648 ce3d 0403
0203 6800 3065 0230 4c34 053f 7cd0 3415
f9d2 3553 680c 780d db13 e70c dcc8 861f
a9cc 8767 e771 119d 0a91 29a8 8bb5 aa14
004c a1a9 eaec 43d9 0231 00ac f1ef 2fd5
dd2f e9a1 74b1 7a51 3846 c3fc 6c30 f112
3f47 ceff fc94 a35e 8051 6b77 8cfc 942d
3d45 1aa7 5ee2 9341 7d1b 57
````

ASN.1 (https://lapo.it/asn1js/)
````
- Certificate SEQUENCE (3 elem)
  - tbsCertificate TBSCertificate SEQUENCE (8 elem)
    - version [0] (1 elem)
      - Version INTEGER 2
    - serialNumber CertificateSerialNumber INTEGER (159 bit) 481762976210496776494547987657568328811820330646
    - signature AlgorithmIdentifier SEQUENCE (1 elem)
      - algorithm OBJECT IDENTIFIER 1.2.840.10045.4.3.2 ecdsaWithSHA256 (ANSI X9.62 ECDSA algorithm with SHA256)
    - issuer rdnSequence Name SEQUENCE (6 elem)
      - RelativeDistinguishedName SET (1 elem)
        - AttributeTypeAndValue SEQUENCE (2 elem)
          - type AttributeType OBJECT IDENTIFIER 2.5.4.6 countryName (X.520 DN component)
          - value AttributeValue [?] PrintableString KR
      - RelativeDistinguishedName SET (1 elem)
        - AttributeTypeAndValue SEQUENCE (2 elem)
          - type AttributeType OBJECT IDENTIFIER 2.5.4.8 stateOrProvinceName (X.520 DN component)
          - value AttributeValue [?] UTF8String KN
      - RelativeDistinguishedName SET (1 elem)
        - AttributeTypeAndValue SEQUENCE (2 elem)
          - type AttributeType OBJECT IDENTIFIER 2.5.4.7 localityName (X.520 DN component)
          - value AttributeValue [?] UTF8String GJ
      - RelativeDistinguishedName SET (1 elem)
        - AttributeTypeAndValue SEQUENCE (2 elem)
          - type AttributeType OBJECT IDENTIFIER 2.5.4.10 organizationName (X.520 DN component)
          - value AttributeValue [?] UTF8String Test
      - RelativeDistinguishedName SET (1 elem)
        - AttributeTypeAndValue SEQUENCE (2 elem)
          - type AttributeType OBJECT IDENTIFIER 2.5.4.11 organizationalUnitName (X.520 DN component)
          - value AttributeValue [?] UTF8String Test
      - RelativeDistinguishedName SET (1 elem)
        - AttributeTypeAndValue SEQUENCE (2 elem)
          - type AttributeType OBJECT IDENTIFIER 2.5.4.3 commonName (X.520 DN component)
          - value AttributeValue [?] UTF8String Test Root
    - validity Validity SEQUENCE (2 elem)
      - notBefore utcTime Time UTCTime 2026-05-13 22:20:02 UTC
      - notAfter utcTime Time UTCTime 2027-05-13 22:20:02 UTC
    - subject rdnSequence Name SEQUENCE (6 elem)
      - RelativeDistinguishedName SET (1 elem)
        - AttributeTypeAndValue SEQUENCE (2 elem)
          - type AttributeType OBJECT IDENTIFIER 2.5.4.6 countryName (X.520 DN component)
          - value AttributeValue [?] PrintableString KR
      - RelativeDistinguishedName SET (1 elem)
        - AttributeTypeAndValue SEQUENCE (2 elem)
          - type AttributeType OBJECT IDENTIFIER 2.5.4.8 stateOrProvinceName (X.520 DN component)
          - value AttributeValue [?] UTF8String KN
      - RelativeDistinguishedName SET (1 elem)
        - AttributeTypeAndValue SEQUENCE (2 elem)
          - type AttributeType OBJECT IDENTIFIER 2.5.4.7 localityName (X.520 DN component)
          - value AttributeValue [?] UTF8String GJ
      - RelativeDistinguishedName SET (1 elem)
        - AttributeTypeAndValue SEQUENCE (2 elem)
          - type AttributeType OBJECT IDENTIFIER 2.5.4.10 organizationName (X.520 DN component)
          - value AttributeValue [?] UTF8String Test
      - RelativeDistinguishedName SET (1 elem)
        - AttributeTypeAndValue SEQUENCE (2 elem)
          - type AttributeType OBJECT IDENTIFIER 2.5.4.11 organizationalUnitName (X.520 DN component)
          - value AttributeValue [?] UTF8String Test
      - RelativeDistinguishedName SET (1 elem)
        - AttributeTypeAndValue SEQUENCE (2 elem)
          - type AttributeType OBJECT IDENTIFIER 2.5.4.3 commonName (X.520 DN component)
          - value AttributeValue [?] UTF8String test.com
    - subjectPublicKeyInfo SubjectPublicKeyInfo SEQUENCE (2 elem)
      - algorithm AlgorithmIdentifier SEQUENCE (2 elem)
        - algorithm OBJECT IDENTIFIER 1.2.840.10045.2.1 ecPublicKey (ANSI X9.62 public key type)
        - parameters ANY OBJECT IDENTIFIER 1.3.132.0.34 secp384r1 (SECG (Certicom) named elliptic curve)
      - subjectPublicKey BIT STRING (776 bit) 0000010010110010011111110100101011001000111000110010011001101001001110…
    - extensions [3] (1 elem)
      - Extensions SEQUENCE (6 elem)
        - Extension SEQUENCE (2 elem)
          - extnID OBJECT IDENTIFIER 2.5.29.19 basicConstraints (X.509 extension)
          - extnValue OCTET STRING (2 byte) 3000
            - SEQUENCE (0 elem)
        - Extension SEQUENCE (2 elem)
          - extnID OBJECT IDENTIFIER 2.5.29.15 keyUsage (X.509 extension)
          - extnValue OCTET STRING (4 byte) 03020780
            - BIT STRING (1 bit) 1
        - Extension SEQUENCE (2 elem)
          - extnID OBJECT IDENTIFIER 2.5.29.37 extKeyUsage (X.509 extension)
          - extnValue OCTET STRING (12 byte) 300A06082B06010505070301
            - SEQUENCE (1 elem)
              - OBJECT IDENTIFIER 1.3.6.1.5.5.7.3.1 serverAuth (PKIX key purpose)
        - Extension SEQUENCE (2 elem)
          - extnID OBJECT IDENTIFIER 2.5.29.17 subjectAltName (X.509 extension)
          - extnValue OCTET STRING (29 byte) 301B8208746573742E636F6D82096C6F63616C686F737487047F000001
            - SEQUENCE (3 elem)
              - [2] (8 byte) test.com
              - [2] (9 byte) localhost
              - [7] (4 byte) 7F000001
        - Extension SEQUENCE (2 elem)
          - extnID OBJECT IDENTIFIER 2.5.29.14 subjectKeyIdentifier (X.509 extension)
          - extnValue OCTET STRING (22 byte) 0414F06A5451F41733FC377F66B194D7C56A78E2F032
            - OCTET STRING (20 byte) F06A5451F41733FC377F66B194D7C56A78E2F032
        - Extension SEQUENCE (2 elem)
          - extnID OBJECT IDENTIFIER 2.5.29.35 authorityKeyIdentifier (X.509 extension)
          - extnValue OCTET STRING (24 byte) 301680146CB3F587BF38EEDFDC869757C69169EA0123134E
            - SEQUENCE (1 elem)
              - [0] (20 byte) 6CB3F587BF38EEDFDC869757C69169EA0123134E
    - signatureAlgorithm AlgorithmIdentifier SEQUENCE (1 elem)
      - algorithm OBJECT IDENTIFIER 1.2.840.10045.4.3.2 ecdsaWithSHA256 (ANSI X9.62 ECDSA algorithm with SHA256)
    - signature BIT STRING (824 bit) 0011000001100101000000100011000001001100001101000000010100111111011111…
      - SEQUENCE (2 elem)
        - INTEGER (383 bit) 1172874671356386011406782248119134935953212620868109242094972487151862…
        - INTEGER (384 bit) 2661868033690839064267418140220413291119663050155277319931341815934778…
````

ASN.1 (https://holtstrom.com/michael/tools/asn1decoder.php)
````
SEQUENCE {
   SEQUENCE {
      [0] {
         INTEGER 0x02 (2 decimal)
      }
      INTEGER 0x5462ffbe6d4b20ec20483b13c7736ad5adafae96
      SEQUENCE {
         OBJECTIDENTIFIER 1.2.840.10045.4.3.2 (ecdsa-with-SHA256)
      }
      SEQUENCE {
         SET {
            SEQUENCE {
               OBJECTIDENTIFIER 2.5.4.6 (countryName)
               PrintableString 'KR'
            }
         }
         SET {
            SEQUENCE {
               OBJECTIDENTIFIER 2.5.4.8 (stateOrProvinceName)
               UTF8String 'KN'
            }
         }
         SET {
            SEQUENCE {
               OBJECTIDENTIFIER 2.5.4.7 (localityName)
               UTF8String 'GJ'
            }
         }
         SET {
            SEQUENCE {
               OBJECTIDENTIFIER 2.5.4.10 (organizationName)
               UTF8String 'Test'
            }
         }
         SET {
            SEQUENCE {
               OBJECTIDENTIFIER 2.5.4.11 (organizationalUnitName)
               UTF8String 'Test'
            }
         }
         SET {
            SEQUENCE {
               OBJECTIDENTIFIER 2.5.4.3 (commonName)
               UTF8String 'Test Root'
            }
         }
      }
      SEQUENCE {
         UTCTime '260513222002Z'
         UTCTime '270513222002Z'
      }
      SEQUENCE {
         SET {
            SEQUENCE {
               OBJECTIDENTIFIER 2.5.4.6 (countryName)
               PrintableString 'KR'
            }
         }
         SET {
            SEQUENCE {
               OBJECTIDENTIFIER 2.5.4.8 (stateOrProvinceName)
               UTF8String 'KN'
            }
         }
         SET {
            SEQUENCE {
               OBJECTIDENTIFIER 2.5.4.7 (localityName)
               UTF8String 'GJ'
            }
         }
         SET {
            SEQUENCE {
               OBJECTIDENTIFIER 2.5.4.10 (organizationName)
               UTF8String 'Test'
            }
         }
         SET {
            SEQUENCE {
               OBJECTIDENTIFIER 2.5.4.11 (organizationalUnitName)
               UTF8String 'Test'
            }
         }
         SET {
            SEQUENCE {
               OBJECTIDENTIFIER 2.5.4.3 (commonName)
               UTF8String 'test.com'
            }
         }
      }
      SEQUENCE {
         SEQUENCE {
            OBJECTIDENTIFIER 1.2.840.10045.2.1 (ecPublicKey)
            OBJECTIDENTIFIER 1.3.132.0.34 (P-384)
         }
         BITSTRING 0x04b27f4ac8e3266939f4281dd902d4274a400974f47a29e48b36642e6733980c5906e4fbce12b64e877af066b24edbc6d7192cbe2174f8fa9fcb4d8f7b07725950a11ea460d127b61671061fe1e17aa7cd0047d9b83ad0edb7c2755e1d151ecc5b : 0 unused bit(s)
      }
      [3] {
         SEQUENCE {
            SEQUENCE {
               OBJECTIDENTIFIER 2.5.29.19 (basicConstraints)
               OCTETSTRING 3000
            }
            SEQUENCE {
               OBJECTIDENTIFIER 2.5.29.15 (keyUsage)
               OCTETSTRING 03020780
            }
            SEQUENCE {
               OBJECTIDENTIFIER 2.5.29.37 (extKeyUsage)
               OCTETSTRING 300a06082b06010505070301
            }
            SEQUENCE {
               OBJECTIDENTIFIER 2.5.29.17 (subjectAltName)
               OCTETSTRING 301b8208746573742e636f6d82096c6f63616c686f737487047f000001
            }
            SEQUENCE {
               OBJECTIDENTIFIER 2.5.29.14 (subjectKeyIdentifier)
               OCTETSTRING 0414f06a5451f41733fc377f66b194d7c56a78e2f032
            }
            SEQUENCE {
               OBJECTIDENTIFIER 2.5.29.35 (authorityKeyIdentifier)
               OCTETSTRING 301680146cb3f587bf38eedfdc869757c69169ea0123134e
            }
         }
      }
   }
   SEQUENCE {
      OBJECTIDENTIFIER 1.2.840.10045.4.3.2 (ecdsa-with-SHA256)
   }
   BITSTRING 0x306502304c34053f7cd03415f9d23553680c780ddb13e70cdcc8861fa9cc8767e771119d0a9129a88bb5aa14004ca1a9eaec43d9023100acf1ef2fd5dd2fe9a174b17a513846c3fc6c30f1123f47cefffc94a35e80516b778cfc942d3d451aa75ee293417d1b57 : 0 unused bit(s)
}
````
