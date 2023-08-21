/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_SOCKET_X509__
#define __HOTPLACE_SDK_NET_SOCKET_X509__

#include <hotplace/sdk/net/types.hpp>
#include <hotplace/sdk/io/stream/stream.hpp>
#include <hotplace/sdk/io/system/datetime.hpp>

namespace hotplace {
using namespace io;
namespace net {

/**
 * @brief self-signed certificate
 * @desc
 *
 *  // server certificate
 *  mkdir certs
 *  touch index.txt
 *  echo "00" > serial
 *  openssl genrsa -aes256 -out certs/server.key 2048
 *  openssl req -new -key certs/server.key -out certs/server.csr -subj '/C=KR/ST=GG/L=Yongin/O=Test Company/OU=Test Dept/CN=Test Part'
 *  openssl x509 -req -days 365 -in certs/server.csr -signkey certs/server.key -out certs/server.crt
 *  openssl genrsa -aes256 -out certs/ca.key 2048
 *  openssl req -new -x509 -days 365 -key certs/ca.key -out certs/ca.csr -subj '/C=KR/ST=GG/L=Yongin/O=Test Company/OU=Test Dept/CN=Test Part'
 *  openssl x509 -x509toreq -days 365 -in certs/ca.csr -signkey certs/ca.key -out certs/ca.req
 *  openssl x509 -req -days 365 -in certs/ca.req -signkey certs/ca.key -out certs/ca.crt
 *
 *  // openssl.conf
 *  [ ca ]
 *      default_ca = CA_default
 *
 *      [ CA_default ]
 *      dir = /opt/openssl/ssl
 *      certs = $dir/certs
 *      crl_dir = $dir/crl
 *      database = $dir/index.txt
 *      serial = $dir/serial
 *      new_certs_dir = $dir/certs
 *
 *      certificate = $certs/ca.crt # The CA certificate
 *      private_key = $certs/ca.key
 *
 *      name_opt = ca_default # Subject Name options
 *      cert_opt = ca_default # Certificate field options
 *
 *      default_days = 3650 # how long to certify for
 *      default_crl_days= 30 # how long before next CRL
 *      #default_md = default # use public key default MD
 *      default_md = sha256 # use public key default MD
 *      preserve = no # keep passed DN ordering
 *      policy = policy_match
 *
 *      # For the CA policy
 *      [ policy_match ]
 *      countryName = match
 *      stateOrProvinceName = optional
 *      organizationName = optional
 *      organizationalUnitName = optional
 *      commonName = supplied
 *      emailAddress = optional
 *
 *  // client certificate
 *  openssl req -new -newkey rsa:2048 -nodes -keyout my.key -out my.csr -subj '/C=KR/ST=GG/L=Yongin/O=Test Company/OU=Test Dept/CN=Test Part'
 *  openssl x509 -req -days 365 -in my.csr -signkey my.key -out my.crt
 *  openssl ca -config openssl.conf -in my.csr # certs/00.pem
 *  openssl pkcs12 -in certs/00.pem -inkey my.key -export -out my.p12
 *  # run google chrome, and register my.p12 at HTTPS/SSL certificate
 *
 *  // example server certificate
 *  SSLCertificateFile      certs/server.crt
 *  SSLCertificateKeyFile   certs/server.key
 *  SSLCertificateChainFile certs/ca.crt
 *  SSLCACertificateFile    certs/ca.crt
 *
 *  // example client certificate
 *  SSL_CTX_set_default_passwd_cb
 *  SSL_CTX_use_certificate_file (certs/00.pem)
 *  SSL_CTX_use_PrivateKey_file (my.key)
 *  SSL_CTX_load_verify_locations/SSL_CTX_add_extra_chain_cert (certs/server.crt)
 */

typedef struct _x509_t {
    SSL_CTX* ssl_ctx;
} x509_t;

enum x509_flag_t {
    x509_verify_client = (1 << 0),
};

/**
 * @brief
 * @param x509_t** context [out]
 */
return_t x509_open (x509_t** context);
/**
 * @brief SSL_CTX*
 * @param x509_t** context [out]
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
 */
return_t x509_open_pem (x509_t** context, const char* cert_file, const char* key_file, const char* password, const char* chain_file);
/**
 * @brief
 * @param x509_t* context [in]
 * @param const char* ciphersuites [in]
 */
return_t x509_set_ciphersuites (x509_t* context, const char* ciphersuites);
/**
 * @brief SSL_CTX_set_verify
 * @param x509_t* context [in]
 * @param int flags [in] SSL_VERIFY_PEER, SSL_VERIFY_FAIL_IF_NO_PEER_CERT, SSL_VERIFY_CLIENT_ONCE
 */
return_t x509_set_verify (x509_t* context, int flags);
/*
 * @brief
 * @param x509_t* context [in]
 */
return_t x509_close (x509_t* context);

}
}  // namespace

#endif
