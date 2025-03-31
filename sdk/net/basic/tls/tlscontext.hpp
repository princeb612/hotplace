/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_BASIC_TLS_TLSCONTEXT__
#define __HOTPLACE_SDK_NET_BASIC_TLS_TLSCONTEXT__

#include <sdk/crypto/basic/types.hpp>

namespace hotplace {
namespace net {

enum tlscontext_flag_t : uint32 {
    tlscontext_flag_tls = (1 << 0),            // using TLS_method
    tlscontext_flag_dtls = (1 << 1),           // using DTLS_method
    tlscontext_flag_allow_tls13 = (1 << 2),    // SSL_CTX_set_max_proto_version(context, TLS1_3_VERSION)
    tlscontext_flag_allow_tls12 = (1 << 3),    // SSL_CTX_set_min_proto_version(context, TLS1_2_VERSION)
    tlscontext_flag_allow_expired = (1 << 5),  // reserved
};

/**
 * @brief certificate
 * @param SSL_CTX** context [out]
 * @param uint32 flag [in] tlscontext_flag_tls or tlscontext_flag_dtls
 * @remarks
 *          tlscontext_flag_tls
 *              to support TLS 1.3 and TLS 1.2
 *                  tlscontext_open_simple(&context, tlscontext_flag_tls);
 *                  tlscontext_open_simple(&context, tlscontext_flag_tls | tlscontext_flag_allow_tls13 | tlscontext_flag_allow_tls12);
 *              to support only TLS 1.3
 *                  tlscontext_open_simple(&context, tlscontext_flag_tls | tlscontext_flag_allow_tls13);
 *              to support only TLS 1.2
 *                  tlscontext_open_simple(&context, tlscontext_flag_tls | tlscontext_flag_allow_tls12);
 *          tlscontext_flag_dtls
 *              openssl not support DTLS 1.3 yet
 *              only works DTLS 1.2
 */
return_t tlscontext_open_simple(SSL_CTX** context, uint32 flag);

/**
 * @brief   SSL_CTX*
 * @param   SSL_CTX** context [out]
 * @param   uint32 flag [in] tlscontext_flag_tls or tlscontext_flag_dtls
 * @param   const char* cert_file [in]
 * @param   const char* key_file [in]
 * @param   const char* password [inopt]
 * @param   const char* chain_file [inopt]
 * @return error code (see error.hpp)
 *      invalid_parameter : check parameters
 *      internal_error_1  : something wrong cert_file
 *      internal_error_2  : something wrong key_file
 *      internal_error_3  : something wrong key_file
 *      internal_error_4  : something wrong chain_file
 *      internal_error_5  : SSL_new fails
 *      intternal_eror_6  : SSL_get_certificate fails
 *      expired           : expired
 * @desc
 *      SSL_CTX_set_default_passwd_cb : set passwd callback for encrypted PEM file handling
 *        encrypted primary key (ex. -----BEGIN ENCRYPTED PRIVATE KEY-----)
 *          openssl 1.x set password parameter
 *          openssl 3.x connection failure ? message (SSL alert number 40, 70)
 *        unencrypted key (ex. -----BEGIN PRIVATE KEY-----)
 *          works good, password parameter useless
 */
return_t tlscontext_open(SSL_CTX** context, uint32 flag, const char* cert_file, const char* key_file, const char* password = nullptr,
                         const char* chain_file = nullptr);

class tlscontext {
   public:
    tlscontext(uint32 flag = tlscontext_flag_tls);
    /**
     * @brief   SSL_CTX*
     * @param   uint32 flags [in] tlscontext_flag_tls, tlscontext_flag_dtls
     * @param   SSL_CTX** context [out]
     * @param   const char* cert_file [in]
     * @param   const char* key_file [in]
     * @param   const char* password [inopt]
     * @param   const char* chain_file [inopt]
     */
    tlscontext(uint32 flag, const char* cert_file, const char* key_file, const char* password = nullptr, const char* chain_file = nullptr);
    ~tlscontext();

    /**
     * SSL_CTX_set_cipher_list
     */
    tlscontext& set_cipher_list(const char* list);
    /**
     * DH_generate_parameters_ex, SSL_CTX_set_tmp_dh
     */
    tlscontext& set_use_dh(int bits);
    /**
     * SSL_CTX_set_verify
     */
    tlscontext& set_verify(int mode);
    /**
     * SSL_CTX_set_alpn_select_cb
     */
    tlscontext& enable_alpn_h2(bool enable);

    /**
     * @brief   call openssl api
     */
    SSL_CTX* get_ctx();

   private:
    SSL_CTX* _ctx;
};

}  // namespace net
}  // namespace hotplace

#endif
