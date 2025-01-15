/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS1_HANDSHAKE_SERVER_HELLO__
#define __HOTPLACE_SDK_NET_TLS1_HANDSHAKE_SERVER_HELLO__

#include <sdk/base/basic/binary.hpp>
#include <sdk/net/tls1/handshake/tls_handshake.hpp>

namespace hotplace {
namespace net {

class tls_handshake_server_hello : public tls_handshake {
   public:
    tls_handshake_server_hello(tls_session* session);

    uint16 get_version();
    binary& get_random();
    binary& get_session_id();
    uint16 get_cipher_suite();
    tls_handshake_server_hello& set_cipher_suite(uint16 cs);
    uint8 get_compression_method();

   protected:
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t do_postprocess(tls_direction_t dir, const byte_t* stream, size_t size, stream_t* debugstream = nullptr);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin, stream_t* debugstream = nullptr);

    uint16 _version;
    binary _random;
    binary _session_id;
    uint16 _cipher_suite;
    uint8 _compression_method;
};

}  // namespace net
}  // namespace hotplace

#endif
