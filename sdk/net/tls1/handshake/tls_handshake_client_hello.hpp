/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS1_HANDSHAKE_CLIENT_HELLO__
#define __HOTPLACE_SDK_NET_TLS1_HANDSHAKE_CLIENT_HELLO__

#include <sdk/net/tls1/handshake/tls_handshake.hpp>

namespace hotplace {
namespace net {

class tls_handshake_client_hello : public tls_handshake {
   public:
    tls_handshake_client_hello(tls_session* session);

    tls_handshake_client_hello& set_random(const binary_t& bin);
    tls_handshake_client_hello& set_random(binary_t&& bin);
    tls_handshake_client_hello& gen_random(uint8 len);
    tls_handshake_client_hello& set_session_id(const binary_t& bin);
    tls_handshake_client_hello& set_session_id(binary_t&& bin);
    tls_handshake_client_hello& gen_session_id(uint8 len);
    tls_handshake_client_hello& add_ciphersuites(const char* ciphersuites);
    tls_handshake_client_hello& add_ciphersuite(uint16 suite);

   protected:
    virtual return_t do_handshake(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t do_read(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t do_construct(tls_direction_t dir, binary_t& bin, stream_t* debugstream = nullptr);

   private:
    binary_t _random;
    binary_t _session_id;
    binary_t _cipher_suites;
};

}  // namespace net
}  // namespace hotplace

#endif
