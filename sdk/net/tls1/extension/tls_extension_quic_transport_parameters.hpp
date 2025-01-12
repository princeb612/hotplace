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

#ifndef __HOTPLACE_SDK_NET_TLS1_EXTENSION_QUIC__
#define __HOTPLACE_SDK_NET_TLS1_EXTENSION_QUIC__

#include <sdk/net/tls1/extension/tls_extension.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   quic_transport_parameters (0x0039)
 */
class tls_extension_quic_transport_parameters : public tls_extension {
   public:
    tls_extension_quic_transport_parameters(tls_session* session);

    virtual return_t do_read_body(const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t write(binary_t& bin, stream_t* debugstream = nullptr);

   protected:
   private:
    std::list<uint64> _keys;
    std::map<uint64, binary_t> _params;
};

}  // namespace net
}  // namespace hotplace

#endif
