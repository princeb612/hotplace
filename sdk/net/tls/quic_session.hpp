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

#ifndef __HOTPLACE_SDK_NET_TLS_QUICSESSION__
#define __HOTPLACE_SDK_NET_TLS_QUICSESSION__

#include <queue>
#include <sdk/base/basic/binaries.hpp>
#include <sdk/base/system/critical_section.hpp>
#include <sdk/net/tls/quic/types.hpp>
#include <sdk/net/tls/quic_streams.hpp>
#include <sdk/net/tls/types.hpp>

namespace hotplace {
namespace net {

class quic_session {
   public:
    quic_session();

    quic_streams& get_quic_streams();

   private:
    quic_streams _streams;
};

}  // namespace net
}  // namespace hotplace

#endif
