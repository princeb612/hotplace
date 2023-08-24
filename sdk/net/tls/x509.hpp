/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_TLS_X509__
#define __HOTPLACE_SDK_NET_TLS_X509__

#include <hotplace/sdk/io/stream/stream.hpp>

namespace hotplace {
using namespace io;
namespace net {

/**
 * @brief self-signed certificate
 * @desc
 *
 *  #!/bin/bash
 *
 *  # root.key
 *  openssl genrsa -aes256 -out root.key 2048
 *  # root.csr
 *  openssl req -new -key root.key -out root.csr -subj '/C=KR/ST=GG/L=YI/O=Test/OU=Test/CN=Test Root'
 *  # review root.csr
 *  openssl req -in root.csr -noout -text
 *  # root.ext
 *  echo "basicConstraints = CA:TRUE" > root.ext
 *  # root.crt
 *  openssl x509 -req -days 3650 -in root.csr -signkey root.key -extfile root.ext -out root.crt
 *  # review root.crt
 *  openssl x509 -text -in root.crt
 *
 *  # server-encrypted.key
 *  openssl genrsa -aes256 -out server-encrypted.key 2048
 *  # server.key
 *  openssl rsa -in server-encrypted.key -out server.key
 *  # server.csr
 *  openssl req -new -key server.key -out server.csr -subj '/C=KR/ST=GG/L=YI/O=Test/OU=Test/CN=Test'
 *  # server.ext
 *  cat << EOF > server.ext
 *  subjectAltName = @alt_names
 *
 *  [alt_names]
 *  DNS = test.princeb612.pe
 *  EOF
 *  # server.crt
 *  openssl x509 -req -days 365 -in server.csr -extfile server.ext -CA root.crt -CAkey root.key -CAcreateserial -out server.crt
 *  # review server.crt
 *  openssl x509 -text -in server.crt
 */

/**
 * @brief certificate
 * @param SSL_CTX** context [out]
 */
return_t x509_open_simple (SSL_CTX** context);
/**
 * @brief certificate
 * @param SSL_CTX** context [out]
 * @param const char* cert_file [in]
 * @param const char* key_file [in]
 * @param const char* password [in]
 * @param const char* chain_file [in]
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
return_t x509_open (SSL_CTX** context, const char* cert_file, const char* key_file,
                    const char* password = nullptr,
                    const char* chain_file = nullptr);

}
}  // namespace

#endif
