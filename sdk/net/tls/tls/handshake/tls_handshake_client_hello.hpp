/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS_TLSHANDSHAKE_CLIENT_HELLO__
#define __HOTPLACE_SDK_NET_TLS_TLSHANDSHAKE_CLIENT_HELLO__

#include <sdk/base/basic/binary.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake.hpp>

namespace hotplace {
namespace net {

/**
 * RFC 5246 7.4.1.2.  Client Hello
 * struct {
 *     ProtocolVersion client_version;
 *     Random random;
 *     SessionID session_id;
 *     CipherSuite cipher_suites<2..2^16-2>;
 *     CompressionMethod compression_methods<1..2^8-1>;
 *     select (extensions_present) {
 *         case false:
 *             struct {};
 *         case true:
 *             Extension extensions<0..2^16-1>;
 *     };
 * } ClientHello;
 */
class tls_handshake_client_hello : public tls_handshake {
   public:
    tls_handshake_client_hello(tls_session* session);

    binary& get_random();
    binary& get_session_id();
    const std::vector<uint16>& get_cipher_suites();
    const std::vector<uint8>& get_compression_methods();

    return_t add_ciphersuites(const char* ciphersuites);
    return_t add_ciphersuite(uint16 suite);

    tls_handshake_client_hello& operator<<(const std::string& ciphersuites);

   protected:
    virtual return_t do_preprocess(tls_direction_t dir);
    virtual return_t do_postprocess(tls_direction_t dir, const byte_t* stream, size_t size);
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);

   private:
    binary _random;  // 32 bytes
    binary _session_id;
    std::vector<uint16> _cipher_suites;
    std::vector<uint8> _compression_methods;
};

}  // namespace net
}  // namespace hotplace

#endif
