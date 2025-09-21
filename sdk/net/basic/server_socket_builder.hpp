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

enum socket_scheme_t : uint32 {
    // 0x0000FFFF
    socket_scheme_tcp = 0x00000000,
    socket_scheme_udp = 0x00000001,
    socket_scheme_tls = 0x00008000,
    socket_scheme_dtls = 0x00008001,
    socket_scheme_quic = 0x00008002,
    socket_scheme_quic2 = 0x00008003,
    // 0x000F0000
    socket_scheme_openssl = 0x00000000,
    socket_scheme_trial = 0x00010000,
    // mask
    socket_scheme_mask = 0x0000ffff,
    socket_scheme_mask_secure = 0x00008000,
    socket_scheme_mask_powered_by = 0x000f0000,
};

class server_socket_builder {
   public:
    server_socket_builder();

    server_socket_builder& set(uint32 scheme);
    server_socket_builder& set_certificate(const std::string& server_cert, const std::string& server_key);
    server_socket_builder& set_ciphersuites(const std::string& cipher_suites);
    server_socket_builder& set_verify(int verify_peer);
    /**
     * auto s = builder.set(scheme).build();
     *
     * (naive_tcp_server_socket*)set(socket_scheme_tcp).build();
     * (naive_udp_server_socket*)set(socket_scheme_udp).build();
     * (openssl_tls_server_socket*)set(socket_scheme_tls | socket_scheme_openssl).set_sertificate(server_cert,
     * server_key).set_ciphersuites(ciphersuites).build(); (openssl_dtls_server_socket*)set(socket_scheme_dtls |
     * socket_scheme_openssl).set_sertificate(server_cert, server_key).set_ciphersuites(ciphersuites).build(); (trial_dtls_server_socket*)set(socket_scheme_dtls
     * | socket_scheme_trial).set_sertificate(server_cert, server_key).set_ciphersuites(ciphersuites).build(); (trial_tls_server_socket*)set(socket_scheme_tls |
     * socket_scheme_trial).set_sertificate(server_cert, server_key).set_ciphersuites(ciphersuites).build(); (trial_quic_server_socket*)set(socket_scheme_quic |
     * socket_scheme_trial).set_sertificate(server_cert, server_key).set_ciphersuites(ciphersuites).build();
     */
    server_socket* build();

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
