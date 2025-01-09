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

#ifndef __HOTPLACE_SDK_NET_TLS1_EXTENSION_PRE_SHARED_KEY__
#define __HOTPLACE_SDK_NET_TLS1_EXTENSION_PRE_SHARED_KEY__

#include <sdk/net/tls1/extension/tls_extension.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   pre_shared_key (0x0029)
 */
class tls_extension_psk : public tls_extension {
   protected:
    tls_extension_psk(tls_session* session);
};

class tls_extension_client_psk : public tls_extension_psk {
   public:
    tls_extension_client_psk(tls_session* session);

    virtual return_t read_data(const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t write(binary_t& bin, stream_t* debugstream = nullptr);

   protected:
   private:
    uint16 _psk_identities_len;
    binary_t _psk_identity;
    uint32 _obfuscated_ticket_age;
    uint16 _psk_binders_len;
    binary_t _psk_binder;
    // size_t _offset_psk_binders_len;
};

class tls_extension_server_psk : public tls_extension_psk {
   public:
    tls_extension_server_psk(tls_session* session);

    virtual return_t read_data(const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t write(binary_t& bin, stream_t* debugstream = nullptr);

   protected:
   private:
    uint16 _selected_identity;
};

}  // namespace net
}  // namespace hotplace

#endif
