/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   types.hpp
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

#include <memory>

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
class crypto_keyexchange;
class crypto_key_object;
class crypto_sign;
class crypto_sign_builder;
class transcript_hash;
class transcript_hash_builder;

class hmac_otp;
class time_otp;

struct BIO_deleter {
    void operator()(BIO* bio) const { BIO_free(bio); }
};
struct BIO_chain_deleter {
    void operator()(BIO* bio) const { BIO_free_all(bio); }
};
struct BN_deleter {
    void operator()(BIGNUM* bn) const { BN_clear_free(bn); }
};
struct BN_CTX_deleter {
    void operator()(BN_CTX* bn_ctx) const { BN_CTX_free(bn_ctx); }
};
struct CMAC_CTX_deleter {
    void operator()(CMAC_CTX* ctx) const { CMAC_CTX_free(ctx); }
};
struct DH_deleter {
    void operator()(DH* dh) const { DH_free(dh); }
};
struct DSA_deleter {
    void operator()(DSA* dsa) const { DSA_free(dsa); }
};
struct DSA_SIG_deleter {
    void operator()(DSA_SIG* dsasig) const { DSA_SIG_free(dsasig); }
};
struct EC_KEY_deleter {
    void operator()(EC_KEY* eckey) const { EC_KEY_free(eckey); }
};
struct EC_POINT_deleter {
    void operator()(EC_POINT* ecpoint) const { EC_POINT_free(ecpoint); }
};
struct EVP_CIPHER_deleter {
    void operator()(EVP_CIPHER* cipher) const { EVP_CIPHER_free(cipher); }
};
struct EVP_CIPHER_CTX_deleter {
    void operator()(EVP_CIPHER_CTX* ctx) const { EVP_CIPHER_CTX_free(ctx); }
};
struct EVP_MD_deleter {
    void operator()(EVP_MD* md) const { EVP_MD_free(md); }
};
struct EVP_MD_CTX_deleter {
    void operator()(EVP_MD_CTX* ctx) const { EVP_MD_CTX_free(ctx); }
};
struct EVP_PKEY_deleter {
    void operator()(EVP_PKEY* pkey) const { EVP_PKEY_free(pkey); }
};
struct EVP_PKEY_CTX_deleter {
    void operator()(EVP_PKEY_CTX* ctx) const { EVP_PKEY_CTX_free(ctx); }
};
struct HMAC_CTX_deleter {
    void operator()(HMAC_CTX* ctx) const { HMAC_CTX_free(ctx); }
};
struct OSSL_DECODER_CTX_deleter {
    void operator()(OSSL_DECODER_CTX* ossldecoder) const { OSSL_DECODER_CTX_free(ossldecoder); }
};
struct OSSL_ENCODER_CTX_deleter {
    void operator()(OSSL_ENCODER_CTX* osslencoder) const { OSSL_ENCODER_CTX_free(osslencoder); }
};
struct RSA_deleter {
    void operator()(RSA* rsa) const { RSA_free(rsa); }
};
struct X509_deleter {
    void operator()(X509* x509) const { X509_free(x509); }
};

using BIO_ptr = std::unique_ptr<BIO, BIO_deleter>;
using BIO_CHAIN_ptr = std::unique_ptr<BIO, BIO_chain_deleter>;
using BN_ptr = std::unique_ptr<BIGNUM, BN_deleter>;
using BN_CTX_ptr = std::unique_ptr<BN_CTX, BN_CTX_deleter>;
using CMAC_CTX_ptr = std::unique_ptr<CMAC_CTX, CMAC_CTX_deleter>;
using DH_ptr = std::unique_ptr<DH, DH_deleter>;
using DSA_ptr = std::unique_ptr<DSA, DSA_deleter>;
using DSA_SIG_ptr = std::unique_ptr<DSA_SIG, DSA_SIG_deleter>;
using EC_KEY_ptr = std::unique_ptr<EC_KEY, EC_KEY_deleter>;
using EC_POINT_ptr = std::unique_ptr<EC_POINT, EC_POINT_deleter>;
using EVP_CIPHER_ptr = std::unique_ptr<EVP_CIPHER, EVP_CIPHER_deleter>;
using EVP_CIPHER_CTX_ptr = std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_deleter>;
using EVP_MD_ptr = std::unique_ptr<EVP_MD, EVP_MD_deleter>;
using EVP_MD_CTX_ptr = std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_deleter>;
using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, EVP_PKEY_deleter>;
using EVP_PKEY_CTX_ptr = std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_deleter>;
using HMAC_CTX_ptr = std::unique_ptr<HMAC_CTX, HMAC_CTX_deleter>;
using OSSL_DECODER_CTX_ptr = std::unique_ptr<OSSL_DECODER_CTX, OSSL_DECODER_CTX_deleter>;
using OSSL_ENCODER_CTX_ptr = std::unique_ptr<OSSL_ENCODER_CTX, OSSL_ENCODER_CTX_deleter>;
using RSA_ptr = std::unique_ptr<RSA, RSA_deleter>;
using X509_ptr = std::unique_ptr<X509, X509_deleter>;

}  // namespace crypto
}  // namespace hotplace

#endif
