/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_CRYPTO_OPENSSL_SDK__
#define __HOTPLACE_SDK_CRYPTO_OPENSSL_SDK__

#include <hotplace/sdk/crypto/types.hpp>

namespace hotplace {
namespace crypto {

#define __min(a, b) (((a) < (b)) ? (a) : (b))
#define __max(a, b) (((a) > (b)) ? (a) : (b))
#define constraint_range(var, minimum, maximum) { var = __max (var, minimum); var = __min (var, maximum); \
}

#define __trace_openssl(x) {  }
#define __leave2_trace_openssl(x) { __leave2; }

#define __trace_inside(x)
#define __trace(x, ...)

/*
 * @brief strings, algorithms
 * @remarks call in main function
 */
void openssl_startup ();
void openssl_cleanup ();
/*
 * @brief openssl thread safe
 * @remarks call in main function
 */
void openssl_thread_setup (void);
void openssl_thread_cleanup (void);
void openssl_thread_end (void);
/*
 * @brief error string
 * @param std::string& str [out]
 */
void openssl_error_string (std::string & str);
return_t trace_openssl (return_t nError);

/* openssl-1.1.1 no older-version compatibility
 * OPENSSL_VERSION_NUMBER MNNFFPPS (major minor fix patch status)
 */
/* API deprecation

    asn1.h
        DEPRECATEDIN_1_1_0(unsigned char *ASN1_STRING_data(ASN1_STRING *x))
    bio.h
        DEPRECATEDIN_1_1_0(struct hostent *BIO_gethostbyname(const char *name))
        DEPRECATEDIN_1_1_0(int BIO_get_port(const char *str, unsigned short *port_ptr))
        DEPRECATEDIN_1_1_0(int BIO_get_host_ip(const char *str, unsigned char *ip))
        DEPRECATEDIN_1_1_0(int BIO_get_accept_socket(char *host_port, int mode))
        DEPRECATEDIN_1_1_0(int BIO_accept(int sock, char **ip_port))
    bn.h
        DEPRECATEDIN_0_9_8(BIGNUM *BN_generate_prime(BIGNUM *ret, int bits, int safe, const BIGNUM *add, const BIGNUM *rem, void (*callback) (int, int, void *), void *cb_arg))
        DEPRECATEDIN_0_9_8(int BN_is_prime(const BIGNUM *p, int nchecks, void (*callback) (int, int, void *), BN_CTX *ctx, void *cb_arg))
        DEPRECATEDIN_0_9_8(int BN_is_prime_fasttest(const BIGNUM *p, int nchecks, void (*callback) (int, int, void *), BN_CTX *ctx, void *cb_arg, int do_trial_division))
        DEPRECATEDIN_0_9_8(void BN_set_params(int mul, int high, int low, int mont))
        DEPRECATEDIN_0_9_8(int BN_get_params(int which)) // 0, mul, 1 high, 2 low, 3 * mont
    conf.h
        DEPRECATEDIN_1_1_0(void OPENSSL_config(const char *config_name))
    dh.h
        DEPRECATEDIN_0_9_8(DH *DH_generate_parameters(int prime_len, int generator, void (*callback) (int, int, void *), void *cb_arg))
    dsa.h
        DEPRECATEDIN_1_2_0(int DSA_sign_setup(DSA *dsa, BN_CTX *ctx_in, BIGNUM **kinvp, BIGNUM **rp))
    ec.h
        DEPRECATEDIN_1_2_0(int EC_GROUP_set_curve_GFp(EC_GROUP *group, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx))
        DEPRECATEDIN_1_2_0(int EC_GROUP_get_curve_GFp(const EC_GROUP *group, BIGNUM *p, BIGNUM *a, BIGNUM *b, BN_CTX *ctx))
        DEPRECATEDIN_1_2_0(int EC_GROUP_set_curve_GF2m(EC_GROUP *group, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx))
        DEPRECATEDIN_1_2_0(int EC_GROUP_get_curve_GF2m(const EC_GROUP *group, BIGNUM *p, BIGNUM *a, BIGNUM *b, BN_CTX *ctx))
        DEPRECATEDIN_1_2_0(int EC_POINT_set_affine_coordinates_GFp(const EC_GROUP *group, EC_POINT *p, const BIGNUM *x, const BIGNUM *y, BN_CTX *ctx))
        DEPRECATEDIN_1_2_0(int EC_POINT_get_affine_coordinates_GFp(const EC_GROUP *group, const EC_POINT *p, BIGNUM *x, BIGNUM *y, BN_CTX *ctx))
        DEPRECATEDIN_1_2_0(int EC_POINT_set_compressed_coordinates_GFp(const EC_GROUP *group, EC_POINT *p, const BIGNUM *x, int y_bit, BN_CTX *ctx))
        DEPRECATEDIN_1_2_0(int EC_POINT_set_affine_coordinates_GF2m(const EC_GROUP *group, EC_POINT *p, const BIGNUM *x, const BIGNUM *y, BN_CTX *ctx))
        DEPRECATEDIN_1_2_0(int EC_POINT_get_affine_coordinates_GF2m(const EC_GROUP *group, const EC_POINT *p, BIGNUM *x, BIGNUM *y, BN_CTX *ctx))
        DEPRECATEDIN_1_2_0(int EC_POINT_set_compressed_coordinates_GF2m(const EC_GROUP *group, EC_POINT *p, const BIGNUM *x, int y_bit, BN_CTX *ctx))
    engine.h
        DEPRECATEDIN_1_1_0(void ENGINE_setup_bsd_cryptodev(void))
    err.h
        DEPRECATEDIN_1_1_0(void ERR_remove_thread_state(void *))
        DEPRECATEDIN_1_0_0(void ERR_remove_state(unsigned long pid))
    hmac.h
        DEPRECATEDIN_1_1_0(__owur int HMAC_Init(HMAC_CTX *ctx, const void *key, int len, const EVP_MD *md))
    pkcs12.h
        DEPRECATEDIN_1_1_0(ASN1_TYPE *PKCS12_get_attr(const PKCS12_SAFEBAG *bag, int attr_nid))
    rand.h
        DEPRECATEDIN_1_1_0(int RAND_pseudo_bytes(unsigned char *buf, int num))
        DEPRECATEDIN_1_1_0(void RAND_screen(void))
        DEPRECATEDIN_1_1_0(int RAND_event(UINT, WPARAM, LPARAM))
    rsa.h
        DEPRECATEDIN_0_9_8(RSA *RSA_generate_key(int bits, unsigned long e, void (*callback) (int, int, void *), void *cb_arg))
    srp.h
        DEPRECATEDIN_1_1_0(SRP_user_pwd *SRP_VBASE_get_by_user(SRP_VBASE *vb, char *username))
    ssl.h
        DEPRECATEDIN_1_1_0(void SSL_set_debug(SSL *s, int debug))
        DEPRECATEDIN_1_1_0(__owur const SSL_METHOD *SSLv3_method(void)) // SSLv3
        DEPRECATEDIN_1_1_0(__owur const SSL_METHOD *SSLv3_server_method(void))
        DEPRECATEDIN_1_1_0(__owur const SSL_METHOD *SSLv3_client_method(void))
        DEPRECATEDIN_1_1_0(__owur const SSL_METHOD *TLSv1_method(void)) // TLSv1.0
        DEPRECATEDIN_1_1_0(__owur const SSL_METHOD *TLSv1_server_method(void))
        DEPRECATEDIN_1_1_0(__owur const SSL_METHOD *TLSv1_client_method(void))
        DEPRECATEDIN_1_1_0(__owur const SSL_METHOD *TLSv1_1_method(void)) // TLSv1.1
        DEPRECATEDIN_1_1_0(__owur const SSL_METHOD *TLSv1_1_server_method(void))
        DEPRECATEDIN_1_1_0(__owur const SSL_METHOD *TLSv1_1_client_method(void))
        DEPRECATEDIN_1_1_0(__owur const SSL_METHOD *TLSv1_2_method(void)) // TLSv1.2
        DEPRECATEDIN_1_1_0(__owur const SSL_METHOD *TLSv1_2_server_method(void))
        DEPRECATEDIN_1_1_0(__owur const SSL_METHOD *TLSv1_2_client_method(void))
        DEPRECATEDIN_1_1_0(__owur const SSL_METHOD *DTLSv1_method(void)) // DTLSv1.0
        DEPRECATEDIN_1_1_0(__owur const SSL_METHOD *DTLSv1_server_method(void))
        DEPRECATEDIN_1_1_0(__owur const SSL_METHOD *DTLSv1_client_method(void))
        DEPRECATEDIN_1_1_0(__owur const SSL_METHOD *DTLSv1_2_method(void))
        DEPRECATEDIN_1_1_0(__owur const SSL_METHOD *DTLSv1_2_server_method(void))
        DEPRECATEDIN_1_1_0(__owur const SSL_METHOD *DTLSv1_2_client_method(void))
    x509.h
        DEPRECATEDIN_1_1_0(ASN1_TIME *X509_CRL_get_lastUpdate(X509_CRL *crl))
        DEPRECATEDIN_1_1_0(ASN1_TIME *X509_CRL_get_nextUpdate(X509_CRL *crl))
 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L

/* openssl-1.1.1 style api */

    #define ASN1_STRING_get0_data(x) ((x)->data)
    #define EVP_PKEY_get0_RSA(x) ((x)->pkey.rsa)
    #define EVP_PKEY_get0_EC_KEY(x) ((x)->pkey.ec)
    #define HMAC_CTX_new() (HMAC_CTX *) calloc (sizeof (HMAC_CTX), 1)
    #define HMAC_CTX_free(x) free (x)
    #define RSA_get0_d(rsa) ((rsa)->d)

    #define RSA_get0_key(rsa, bn_n, bn_e, bn_d) \
    *(bn_n) = (rsa)->n; \
    *(bn_e) = (rsa)->e; \
    *(bn_d) = (rsa)->d;

    #define RSA_get0_factors(rsa, bn_p, bn_q) \
    *(bn_p) = (rsa)->p; \
    *(bn_q) = (rsa)->q;

    #define RSA_get0_crt_params(rsa, bn_dmp1, bn_dmq1, bn_iqmp) \
    *(bn_dmp1) = (rsa)->dmp1; \
    *(bn_dmq1) = (rsa)->dmq1; \
    *(bn_iqmp) = (rsa)->iqmp;

    #define RSA_set0_key(rsa, bn_n, bn_e, bn_d) \
    if ((rsa)->n) { \
        BN_free ((rsa)->n); \
    } \
    (rsa)->n = bn_n; \
    if ((rsa)->e) { \
        BN_free ((rsa)->e); \
    } \
    (rsa)->e = bn_e; \
    if ((rsa)->d) { \
        BN_free ((rsa)->d); \
    } \
    (rsa)->d = bn_d;

    #define RSA_set0_factors(rsa, bn_p, bn_q) \
    if ((rsa)->p) { \
        BN_free ((rsa)->p); \
    } \
    (rsa)->p = bn_p; \
    if ((rsa)->q) { \
        BN_free ((rsa)->q); \
    } \
    (rsa)->q = bn_q;

    #define RSA_set0_crt_params(rsa, bn_dmp1, bn_dmq1, bn_iqmp) \
    if ((rsa)->dmp1) { \
        BN_free ((rsa)->dmp1); \
    } \
    (rsa)->dmp1 = bn_dmp1; \
    if ((rsa)->dmq1) { \
        BN_free ((rsa)->dmq1); \
    } \
    (rsa)->dmq1 = bn_dmq1; \
    if ((rsa)->iqmp) { \
        BN_free ((rsa)->iqmp); \
    } \
    (rsa)->iqmp = bn_iqmp;

    #define SSL_CTX_get_default_passwd_cb(ctx) ((ctx)->default_passwd_callback)
    #define SSL_CTX_get_default_passwd_cb_userdata(ctx) ((ctx)->default_passwd_callback_userdata)
    #define X509_STORE_CTX_get_current_cert(ctx) ((ctx)->current_cert)

    #define ECDSA_SIG_get0(x, bn_r, bn_s) *bn_r = x->r; *bn_s = x->s;
    #define ECDSA_SIG_set0(x, bn_r, bn_s) x->r = bn_r; x->s = bn_s;

    #define X509_LOOKUP_get_store(ctx) ((ctx)->store_ctx)
#else

//#define EVP_CIPHER_CTX_init(x) EVP_CIPHER_CTX_reset(x)
//#define EVP_CIPHER_CTX_cleanup(x) EVP_CIPHER_CTX_reset(x)

#endif

/*
 * @brief set a cooltime to sleep while inflate and deflate
 * @param uint32 ms [in] milliseconds, it can't be greater than ossl_cooltime_max.
 * @return
 *      errorcode_t::success
 *      errorcode_t::out_of_range - if given value is greater than ossl_cooltime_max
 * @remarks
 *      by default, ossl_cooltime_max is 1000ms (1second)
 */
return_t ossl_set_cooltime (uint32 ms);
/*
 * @brief set a max cooltime to sleep while inflate and deflate
 * @param uint32 ms [in] milliseconds, cannot be zero
 * @return
 *      errorcode_t::invalid_parameter - if given value is zero or lesser than current ossl_cooltime
 */
return_t ossl_set_cooltime_max (uint32 ms);
/*
 * @biref return a cooltime
 */
uint32 ossl_get_cooltime ();
/*
 * @brief take a break after processing
 * @param uint32 blocks [in]
 * @return
 *      errorcode_t::invalid_parameter - cannot be zero
 */
return_t ossl_set_unitsize (uint32 bytes);
/*
 * @brief return ossl_cooltime_unitsize
 *        default 4096 bytes
 */
uint32 ossl_get_unitsize ();

/*
 * @brief is private key
 * @param EVP_PKEY* pkey [in]
 * @param bool& result [out]
 * @return error code (see error.hpp)
 */
return_t is_private_key (EVP_PKEY * pkey, bool& result);

//
//

/*
 * @brief kindof
 * @param crypto_key_t type [in]
 */
bool kindof_ecc (crypto_key_t type);
/*
 * @brief kty from key
 * @param crypto_key_t type
 * @return oct, RSA, EC, OKP
 */
const char* nameof_key_type (crypto_key_t type);

}
}  // namespace

#endif
