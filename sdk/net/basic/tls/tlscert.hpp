/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_TLS_CERT__
#define __HOTPLACE_SDK_NET_TLS_CERT__

#include <sdk/crypto/basic/types.hpp>

namespace hotplace {
namespace net {

enum tlscert_flag_t {
    tlscert_flag_tls = (1 << 0),
    tlscert_flag_dtls = (1 << 1),
    tlscert_flag_allow_expired = (1 << 5),  // reserved
};

/**
 * @brief certificate
 * @param uint32 flag [in] tlscert_flag_tls or tlscert_flag_dtls
 * @param SSL_CTX** context [out]
 */
return_t tlscert_open_simple(uint32 flag, SSL_CTX** context);

/**
 * @brief   SSL_CTX*
 * @param   uint32 flag [in] tlscert_flag_tls or tlscert_flag_dtls
 * @param   SSL_CTX** context [out]
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
return_t tlscert_open(uint32 flag, SSL_CTX** context, const char* cert_file, const char* key_file, const char* password = nullptr,
                      const char* chain_file = nullptr);

class tlscert {
   public:
    tlscert(uint32 flag = tlscert_flag_tls);
    /**
     * @brief   SSL_CTX*
     * @param   uint32 flags [in] tlscert_flag_tls, tlscert_flag_dtls
     * @param   SSL_CTX** context [out]
     * @param   const char* cert_file [in]
     * @param   const char* key_file [in]
     * @param   const char* password [inopt]
     * @param   const char* chain_file [inopt]
     */
    tlscert(uint32 flag, const char* cert_file, const char* key_file, const char* password = nullptr, const char* chain_file = nullptr);
    ~tlscert();

    /**
     * SSL_CTX_set_cipher_list
     */
    tlscert& set_cipher_list(const char* list);
    /**
     * DH_generate_parameters_ex, SSL_CTX_set_tmp_dh
     */
    tlscert& set_use_dh(int bits);
    /**
     * SSL_CTX_set_verify
     */
    tlscert& set_verify(int mode);
    /**
     * SSL_CTX_set_alpn_select_cb
     */
    tlscert& enable_alpn_h2(bool enable);

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
