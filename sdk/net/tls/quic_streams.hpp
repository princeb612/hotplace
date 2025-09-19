/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_TLS_QUICSTREAMS__
#define __HOTPLACE_SDK_NET_TLS_QUICSTREAMS__

#include <string.h>

#include <hotplace/sdk/base/basic/binaries.hpp>

namespace hotplace {
namespace net {

/**
 * QUIC FRAME STREAM specific implementation
 */
class quic_streams : public t_binaries<uint64, uint8> {
   public:
    quic_streams();

    // set_tag
    return_t set_unistream_type(uint64 stream_id, uint8 type);
    // get_tag
    return_t get_unistream_type(uint64 stream_id, uint8& type);

    bool is_unidirectional_stream(uint64 stream_id);

   protected:
   private:
};

}  // namespace net
}  // namespace hotplace

#endif
