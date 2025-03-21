/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS_TLSHANDSHAKE_ENCRYPTED_EXTENSIONS__
#define __HOTPLACE_SDK_NET_TLS_TLSHANDSHAKE_ENCRYPTED_EXTENSIONS__

#include <sdk/net/tls/tls/handshake/tls_handshake.hpp>

namespace hotplace {
namespace net {

/**
 * @example
 *          tls_record_application_data record(session);
 *          auto handshake = new tls_handshake_encrypted_extensions(session);
 *
 *          auto extension = new tls_extension_alpn(session);
 *          binary_t protocols;
 *          binary_append(protocols, uint8(2));
 *          binary_append(protocols, "h2");
 *          binary_append(protocols, uint8(8));
 *          binary_append(protocols, "http/1.1");
 *          extension->set_protocols(protocols);
 *
 *          record.get_handshakes().add(handshake);
 *          record.write(from_client, packet);  // C -> S
 */
class tls_handshake_encrypted_extensions : public tls_handshake {
   public:
    tls_handshake_encrypted_extensions(tls_session* session);

   protected:
    virtual return_t do_postprocess(tls_direction_t dir, const byte_t* stream, size_t size);
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);
};

}  // namespace net
}  // namespace hotplace

#endif
