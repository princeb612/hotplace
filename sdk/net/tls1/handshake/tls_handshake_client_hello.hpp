/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS1_HANDSHAKE_CLIENT_HELLO__
#define __HOTPLACE_SDK_NET_TLS1_HANDSHAKE_CLIENT_HELLO__

#include <sdk/base/basic/binary.hpp>
#include <sdk/net/tls1/handshake/tls_handshake.hpp>

namespace hotplace {
namespace net {

class tls_handshake_client_hello : public tls_handshake {
   public:
    tls_handshake_client_hello(tls_session* session);

    uint16 get_version();
    binary& get_random();
    binary& get_session_id();
    const std::vector<uint16>& get_cipher_suites();
    const std::vector<uint8>& get_compression_methods();

    return_t add_ciphersuites(const char* ciphersuites);
    return_t add_ciphersuite(uint16 suite);

   protected:
    virtual return_t do_preprocess(tls_direction_t dir, const byte_t* stream, size_t size);
    virtual return_t do_postprocess(tls_direction_t dir, const byte_t* stream, size_t size);
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);

   private:
    uint16 _version;
    binary _random;
    binary _session_id;
    std::vector<uint16> _cipher_suites;
    std::vector<uint8> _compression_methods;
};

class tls_handshake_client_hello_selector {
   public:
    tls_handshake_client_hello_selector(const tls_records* records);

    const tls_records* get_records();
    return_t select();
    uint16 get_version();
    uint16 get_cipher_suite();

   protected:
    const tls_records* _records;
    uint16 _version;
    uint16 _cipher_suite;
};

}  // namespace net
}  // namespace hotplace

#endif
