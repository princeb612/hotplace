/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_CRYPTO_BASIC_TYPES__
#define __HOTPLACE_SDK_CRYPTO_BASIC_TYPES__

#include <hotplace/sdk/crypto/types.hpp>

#define OPENSSL_API_COMPAT 10101

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/cmac.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/idea.h>
#include <openssl/kdf.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/pem.h>
#include <openssl/ripemd.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
// #include <openssl/whrlpool.h>
#include <openssl/x509v3.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#else
// avoid compile error
struct OSSL_LIB_CTX { /* dummy */
};
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30200000L
#include <openssl/hpke.h>
#include <openssl/thread.h>
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#else
#endif

namespace hotplace {
namespace crypto {

class openssl_crypt;
class openssl_digest;
class openssl_hash;
class openssl_hpke;
class openssl_kdf;
class openssl_mac;
class openssl_prng;
class openssl_sign;

class cipher_encrypt;
class cipher_encrypt_builder;

class crypto_advisor;
class crypto_aead;
class crypto_aead_builder;
class crypto_cbc_hmac;
class crypto_encrypt;
class crypto_encrypt_builder;
class crypto_hash;
class crypto_hash_builder;
class crypto_hmac;
class crypto_hmac_builder;
class crypto_key;
class crypto_keychain;
class crypto_key_object;
class crypto_sign;
class crypto_sign_builder;
class transcript_hash;
class transcript_hash_builder;

class hmac_otp;
class time_otp;

}  // namespace crypto
}  // namespace hotplace

#endif
