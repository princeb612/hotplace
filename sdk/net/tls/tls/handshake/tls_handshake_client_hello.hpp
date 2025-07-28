/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS_TLS_HANDSHAKE_TLSHANDSHAKECLIENTHELLO__
#define __HOTPLACE_SDK_NET_TLS_TLS_HANDSHAKE_TLSHANDSHAKECLIENTHELLO__

#include <sdk/base/basic/binary.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake.hpp>

namespace hotplace {
namespace net {

/**
 * @remarks
 *          RFC 5246 7.4.1.2.  Client Hello
 *          struct {
 *              ProtocolVersion client_version;
 *              Random random;
 *              SessionID session_id;
 *              CipherSuite cipher_suites<2..2^16-2>;
 *              CompressionMethod compression_methods<1..2^8-1>;
 *              select (extensions_present) {
 *                  case false:
 *                      struct {};
 *                  case true:
 *                      Extension extensions<0..2^16-1>;
 *              };
 *          } ClientHello;
 * @example
 *          binary_t packet;
 *          tls_record_handshake record(session);
 *          auto handshake = new tls_handshake_client_hello(session);
 *          openssl_prng prng;
 *
 *          prng.random(random, 32);
 *          handshake->set_random(random);
 *
 *          prng.random(session_id, 32);
 *          handshake->set_session_id(session_id);
 *
 *          handshake->add_ciphersuites("TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256");
 *
 *          auto ec_point_formats = new tls_extension_ec_point_formats(session);
 *          ec_point_formats->add("uncompressed");
 *          handshake->get_extensions().add(ec_point_formats);
 *
 *          auto supported_groups = new tls_extension_supported_groups(session);
 *          (*supported_groups).add("x25519").add("secp256r1");
 *          handshake->get_extensions().add(supported_groups);
 *
 *          auto signature_algorithms = new tls_extension_signature_algorithms(session);
 *          (*signature_algorithms).add("ecdsa_secp256r1_sha256").add("ed25519");
 *          handshake->get_extensions().add(signature_algorithms);
 *
 *          auto supported_versions = new tls_extension_client_supported_versions(session);
 *          (*supported_versions).add(tls_13);
 *          handshake->get_extensions().add(supported_versions);
 *
 *          auto key_share = new tls_extension_client_key_share(session);
 *          key_share->add("x25519");
 *          handshake->get_extensions().add(key_share);
 *
 *          record.get_handshakes().add(handshake);
 *          record.write(from_client, packet);
 */
class tls_handshake_client_hello : public tls_handshake {
   public:
    tls_handshake_client_hello(tls_session* session);
    virtual ~tls_handshake_client_hello();

    void set_random(const binary_t& value);
    void set_session_id(const binary_t& value);
    void set_cookie(const binary_t& cookie);
    const binary_t& get_random();
    const binary_t& get_session_id();
    const binary_t& get_cookie();
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
    binary_t _random;  // 32 bytes
    binary_t _session_id;
    binary_t _cookie;
    std::vector<uint16> _cipher_suites;
    std::vector<uint8> _compression_methods;
};

}  // namespace net
}  // namespace hotplace

#endif
