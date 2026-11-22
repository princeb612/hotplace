/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_extension_session_ticket.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc   RFC 5077 SessionTicket extension for TLS 1.2.
 */

#ifndef __HOTPLACE_SDK_NET_TLS_TLS_EXTENSION_TLSEXTENSIONSESSIONTICKET__
#define __HOTPLACE_SDK_NET_TLS_TLS_EXTENSION_TLSEXTENSIONSESSIONTICKET__

#include <hotplace/sdk/base/nostd/binary.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   RFC 5077 SessionTicket extension
 *
 * ClientHello carries an opaque ticket (or an empty body to request one).
 * ServerHello carries an empty body to acknowledge ticket issuance.
 */
class HOTPLACE_NET_API tls_extension_session_ticket : public tls_extension {
   public:
    explicit tls_extension_session_ticket(tls_handshake* handshake);
    virtual ~tls_extension_session_ticket();

    const binary_t& get_ticket() const;
    void set_ticket(const binary_t& ticket);

   protected:
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);

   private:
    binary_t _ticket;
};

}  // namespace net
}  // namespace hotplace

#endif
