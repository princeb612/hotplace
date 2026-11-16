/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_extension_pre_shared_key.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS_TLS_EXTENSION_TLSEXTENSIONPRESHAREDKEY__
#define __HOTPLACE_SDK_NET_TLS_TLS_EXTENSION_TLSEXTENSIONPRESHAREDKEY__

#include <hotplace/sdk/net/tls/tls/extension/tls_extension.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   pre_shared_key (0x0029)
 */
class HOTPLACE_NET_API tls_extension_psk : public tls_extension {
   protected:
    tls_extension_psk(tls_handshake* handshake);
    virtual ~tls_extension_psk();
};

class HOTPLACE_NET_API tls_extension_client_psk : public tls_extension_psk {
   public:
    tls_extension_client_psk(tls_handshake* handshake);
    virtual ~tls_extension_client_psk();

    size_t get_binder_list_offset() const;
    uint16 get_identity_count() const;
    const std::vector<binary_t>& get_binder_psks() const;
    const std::vector<binary_t>& get_identities() const;

   protected:
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);

   private:
    uint16 _psk_identities_len;
    binary_t _psk_identity;
    uint32 _obfuscated_ticket_age;
    uint16 _psk_binders_len;
    binary_t _psk_binder;
    size_t _binder_list_offset;
    uint16 _identity_count;
    std::vector<binary_t> _identities;
    std::vector<binary_t> _binder_psks;
};

class HOTPLACE_NET_API tls_extension_server_psk : public tls_extension_psk {
   public:
    tls_extension_server_psk(tls_handshake* handshake);
    virtual ~tls_extension_server_psk();
    uint16 get_selected_identity() const;
    void set_selected_identity(uint16 selected_identity);

   protected:
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);

   private:
    uint16 _selected_identity;
};

}  // namespace net
}  // namespace hotplace

#endif
