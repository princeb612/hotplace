/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_BASIC_SERVERSOCKETBUILDER__
#define __HOTPLACE_SDK_NET_BASIC_SERVERSOCKETBUILDER__

#include <hotplace/sdk/net/basic/types.hpp>

namespace hotplace {
namespace net {

/**
 * @example
 *          server_socket_builder builder;
 *          tls_socket = builder
 *                          .set(socket_scheme_tls | socket_scheme_openssl)
 *                          .set_certificate("rsa.crt", "rsa.key")
 *                          .set_ciphersuites(ciphersuites)
 *                          .set_verify(0)
 *                          .build();
 */
class server_socket_builder {
   public:
    server_socket_builder();

    /**
     * @param   uint32 scheme [in] socket_scheme_t
     */
    server_socket_builder& set(uint32 scheme);
    /**
     * @param   const std::string& server_cert [in]
     * @param   const std::string& server_key [in]
     */
    server_socket_builder& set_certificate(const std::string& server_cert, const std::string& server_key);
    /**
     * @param   const std::string& cipher_suites [in]
     */
    server_socket_builder& set_ciphersuites(const std::string& cipher_suites);
    /**
     * @param   int verify_peer [in]
     */
    server_socket_builder& set_verify(int verify_peer);
    /**
     * @brief   build
     */
    server_socket* build();
    /**
     * @example
     *          server_socket_builder builder;
     *          adapter = builder
     *                          .set(socket_scheme_openssl)
     *                          .build_adapter();
     */
    server_socket_adapter* build_adapter();

    uint32 get_scheme();

   protected:
   private:
    uint32 _scheme;
    std::string _server_cert;
    std::string _server_key;
    std::string _cipher_suites;
    int _verify;
};

}  // namespace net
}  // namespace hotplace

#endif
