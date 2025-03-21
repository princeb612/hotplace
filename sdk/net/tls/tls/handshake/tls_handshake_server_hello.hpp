/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS_TLSHANDSHAKE_SERVER_HELLO__
#define __HOTPLACE_SDK_NET_TLS_TLSHANDSHAKE_SERVER_HELLO__

#include <sdk/base/basic/binary.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake.hpp>

namespace hotplace {
namespace net {

/**
 * @remarks
 *          RFC 5246 7.4.1.3.  Server Hello
 *          struct {
 *              ProtocolVersion server_version;
 *              Random random;
 *              SessionID session_id;
 *              CipherSuite cipher_suite;
 *              CompressionMethod compression_method;
 *              select (extensions_present) {
 *                  case false:
 *                      struct {};
 *                  case true:
 *                      Extension extensions<0..2^16-1>;
 *              };
 *          } ServerHello;
 * @example
 *          tls_record_handshake record(session);
 *          auto handshake = new tls_handshake_server_hello(session);
 *          openssl_prng prng;
 *
 *          prng.random(random, 32);
 *          handshake->set_random(random);
 *
 *          prng.random(session_id, 32);
 *          handshake->set_session_id(session_id);
 *
 *          handshake->set_cipher_suite("TLS_AES_128_GCM_SHA256");
 *
 *          auto supported_version = new tls_extension_server_supported_versions(session);
 *          supported_version->set(tls_13);
 *          handshake->get_extensions().add(supported_version);
 *
 *          auto key_share = new tls_extension_server_key_share(session);
 *          key_share->add_keyshare();
 *          handshake->get_extensions().add(key_share);
 *
 *          record.get_handshakes().add(handshake);
 */
class tls_handshake_server_hello : public tls_handshake {
   public:
    tls_handshake_server_hello(tls_session* session);

    void set_random(const binary_t& value);
    void set_session_id(const binary_t& value);
    const binary& get_random();
    const binary& get_session_id();
    uint16 get_cipher_suite();
    return_t set_cipher_suite(uint16 cs);
    return_t set_cipher_suite(const char* cs);
    uint8 get_compression_method();

   protected:
    virtual return_t do_postprocess(tls_direction_t dir, const byte_t* stream, size_t size);
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);

   private:
    binary _random;  // 32 bytes
    binary _session_id;
    uint8 _compression_method;
};

}  // namespace net
}  // namespace hotplace

#endif
