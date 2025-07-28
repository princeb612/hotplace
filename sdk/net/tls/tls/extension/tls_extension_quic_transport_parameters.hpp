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

#ifndef __HOTPLACE_SDK_NET_TLS_TLS_EXTENSION_TLSEXTENSIONQUICTRANSPORTPARAMETERS__
#define __HOTPLACE_SDK_NET_TLS_TLS_EXTENSION_TLSEXTENSIONQUICTRANSPORTPARAMETERS__

#include <sdk/net/tls/tls/extension/tls_extension.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   quic_transport_parameters (0x0039)
 */
class tls_extension_quic_transport_parameters : public tls_extension {
   public:
    tls_extension_quic_transport_parameters(tls_handshake* handshake);
    virtual ~tls_extension_quic_transport_parameters();

    tls_extension_quic_transport_parameters& set(uint64 id, uint64 value);
    tls_extension_quic_transport_parameters& set(uint64 id, const binary_t& value);

   protected:
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);

   private:
    critical_section _lock;
    std::list<std::pair<uint64, binary_t>> _params;
};

}  // namespace net
}  // namespace hotplace

#endif
