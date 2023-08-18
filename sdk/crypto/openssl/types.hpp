/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_CRYPTO_OPENSSL_TYPES__
#define __HOTPLACE_SDK_CRYPTO_OPENSSL_TYPES__

#include <hotplace/sdk/crypto/types.hpp>

#define OPENSSL_API_COMPAT 10101

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/pem.h>
#include <openssl/ripemd.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
//#include <openssl/whrlpool.h>
#include <openssl/x509v3.h>

namespace hotplace {
namespace crypto {

typedef struct _openssl_evp_cipher_method_t {
    crypt_symmetric_t _algorithm;
    crypt_mode_t _mode;
    const EVP_CIPHER* _cipher; //const EVP_CIPHER* _cipher;
    const char* _fetchname;
} openssl_evp_cipher_method_t;

typedef struct _openssl_evp_md_method_t {
    hash_algorithm_t _algorithm;
    const EVP_MD* _evp_md;
    const char* _fetchname;
} openssl_evp_md_method_t;

/* opensource native type

 # define EVP_PKEY_HMAC     NID_hmac
 # define EVP_PKEY_RSA      NID_rsaEncryption
 # define EVP_PKEY_EC       NID_X9_62_id_ecPublicKey
 # define EVP_PKEY_X25519   NID_X25519
 # define EVP_PKEY_X448     NID_X448
 # define EVP_PKEY_ED25519  NID_ED25519
 # define EVP_PKEY_ED448    NID_ED448

 #define NID_hmac                   855
 #define NID_rsaEncryption          6
 #define NID_X9_62_id_ecPublicKey   408
 #define NID_X25519                 1034
 #define NID_X448                   1035
 #define NID_ED25519                1087
 #define NID_ED448                  1088

 #define NID_X9_62_prime256v1       415
 #define NID_secp384r1              715
 #define NID_secp521r1              716
 */


}
}  // namespace

#endif
