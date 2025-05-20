/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS_TLS_EXTENSION_TLSEXTENSIONENCRYPTEDCLIENTHELLO__
#define __HOTPLACE_SDK_NET_TLS_TLS_EXTENSION_TLSEXTENSIONENCRYPTEDCLIENTHELLO__

#include <sdk/net/tls/tls/extension/tls_extension.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   encrypted_client_hello (0xfe0d)
 */
class tls_extension_encrypted_client_hello : public tls_extension {
   public:
    tls_extension_encrypted_client_hello(tls_session* session);

   protected:
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);

   private:
    uint8 _client_hello_type;
    uint16 _kdf;
    uint16 _aead;
    uint8 _config_id;
    uint16 _enc_len;
    binary_t _enc;
    uint16 _enc_payload_len;
    binary_t _enc_payload;
};

}  // namespace net
}  // namespace hotplace

#endif
