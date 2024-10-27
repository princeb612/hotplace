/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_CRYPTO_OPENSSL_SDK__
#define __HOTPLACE_SDK_CRYPTO_OPENSSL_SDK__

#include <sdk/crypto/basic/types.hpp>

namespace hotplace {
namespace crypto {

/**
 * @brief strings, algorithms
 * @remarks call in main function
 */
void openssl_startup();
void openssl_cleanup();
/**
 * @brief openssl thread safe
 * @remarks call in main function
 */
void openssl_thread_setup(void);
void openssl_thread_cleanup(void);
void openssl_thread_end(void);

return_t get_opensslerror(int rc);
return_t trace_openssl(return_t errorcode);
return_t debug_trace_openssl(stream_t* stream);
#define __leave2_trace_openssl(x)       \
    if (errorcode_t::success != x) {    \
        __footprints(x);                \
    }                                   \
    hotplace::crypto::trace_openssl(x); \
    __leave2;

/* openssl-1.1.1 no older-version compatibility
 * OPENSSL_VERSION_NUMBER MNNFFPPS (major minor fix patch status)
 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L

/* openssl-1.1.1 style api */

#define ASN1_STRING_get0_data(x) ((x)->data)
#define EVP_PKEY_get0_RSA(x) ((x)->pkey.rsa)
#define EVP_PKEY_get0_EC_KEY(x) ((x)->pkey.ec)
#define HMAC_CTX_new() (HMAC_CTX*)calloc(sizeof(HMAC_CTX), 1)
#define HMAC_CTX_free(x) free(x)
#define RSA_get0_d(rsa) ((rsa)->d)

#define RSA_get0_key(rsa, bn_n, bn_e, bn_d) \
    *(bn_n) = (rsa)->n;                     \
    *(bn_e) = (rsa)->e;                     \
    *(bn_d) = (rsa)->d;

#define RSA_get0_factors(rsa, bn_p, bn_q) \
    *(bn_p) = (rsa)->p;                   \
    *(bn_q) = (rsa)->q;

#define RSA_get0_crt_params(rsa, bn_dmp1, bn_dmq1, bn_iqmp) \
    *(bn_dmp1) = (rsa)->dmp1;                               \
    *(bn_dmq1) = (rsa)->dmq1;                               \
    *(bn_iqmp) = (rsa)->iqmp;

#define RSA_set0_key(rsa, bn_n, bn_e, bn_d) \
    if ((rsa)->n) {                         \
        BN_free((rsa)->n);                  \
    }                                       \
    (rsa)->n = bn_n;                        \
    if ((rsa)->e) {                         \
        BN_free((rsa)->e);                  \
    }                                       \
    (rsa)->e = bn_e;                        \
    if ((rsa)->d) {                         \
        BN_free((rsa)->d);                  \
    }                                       \
    (rsa)->d = bn_d;

#define RSA_set0_factors(rsa, bn_p, bn_q) \
    if ((rsa)->p) {                       \
        BN_free((rsa)->p);                \
    }                                     \
    (rsa)->p = bn_p;                      \
    if ((rsa)->q) {                       \
        BN_free((rsa)->q);                \
    }                                     \
    (rsa)->q = bn_q;

#define RSA_set0_crt_params(rsa, bn_dmp1, bn_dmq1, bn_iqmp) \
    if ((rsa)->dmp1) {                                      \
        BN_free((rsa)->dmp1);                               \
    }                                                       \
    (rsa)->dmp1 = bn_dmp1;                                  \
    if ((rsa)->dmq1) {                                      \
        BN_free((rsa)->dmq1);                               \
    }                                                       \
    (rsa)->dmq1 = bn_dmq1;                                  \
    if ((rsa)->iqmp) {                                      \
        BN_free((rsa)->iqmp);                               \
    }                                                       \
    (rsa)->iqmp = bn_iqmp;

#define SSL_CTX_get_default_passwd_cb(ctx) ((ctx)->default_passwd_callback)
#define SSL_CTX_get_default_passwd_cb_userdata(ctx) ((ctx)->default_passwd_callback_userdata)
#define X509_STORE_CTX_get_current_cert(ctx) ((ctx)->current_cert)

#define ECDSA_SIG_get0(x, bn_r, bn_s) \
    *bn_r = x->r;                     \
    *bn_s = x->s;
#define ECDSA_SIG_set0(x, bn_r, bn_s) \
    x->r = bn_r;                      \
    x->s = bn_s;

#define X509_LOOKUP_get_store(ctx) ((ctx)->store_ctx)
#else

//#define EVP_CIPHER_CTX_init(x) EVP_CIPHER_CTX_reset(x)
//#define EVP_CIPHER_CTX_cleanup(x) EVP_CIPHER_CTX_reset(x)

#endif

/**
 * @brief set a cooltime to sleep while encryt and decrypt
 * @param uint32 ms [in] milliseconds, it can't be greater than ossl_cooltime_max.
 * @return
 *      errorcode_t::success
 *      errorcode_t::out_of_range - if given value is greater than ossl_cooltime_max
 * @remarks
 *      by default, ossl_cooltime_max is 1000ms (1second)
 */
return_t ossl_set_cooltime(uint32 ms);
/**
 * @brief set a max cooltime to sleep while encryt and decrypt
 * @param uint32 ms [in] milliseconds, cannot be zero
 * @return
 *      errorcode_t::invalid_parameter - if given value is zero or lesser than current ossl_cooltime
 */
return_t ossl_set_cooltime_max(uint32 ms);
/**
 * @biref return a cooltime
 */
uint32 ossl_get_cooltime();
/**
 * @brief take a break after processing
 * @param uint32 blocks [in]
 * @return
 *      errorcode_t::invalid_parameter - cannot be zero
 */
return_t ossl_set_unitsize(uint32 bytes);
/**
 * @brief return ossl_cooltime_unitsize
 *        default 4096 bytes
 */
uint32 ossl_get_unitsize();

}  // namespace crypto
}  // namespace hotplace

#endif
