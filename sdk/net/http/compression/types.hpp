/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_COMPRESSION_TYPES__
#define __HOTPLACE_SDK_NET_HTTP_COMPRESSION_TYPES__

#include <functional>
#include <hotplace/sdk/net/http/types.hpp>
#include <queue>

namespace hotplace {
namespace net {

enum header_compression_type_t {
    header_compression_hpack = 0,
    header_compression_qpack = 1,
};

enum header_compression_cmd_t {
    hpack_cmd_inserted = 1,
    qpack_cmd_inserted = 1,
    hpack_cmd_dropped = 2,
    qpack_cmd_dropped = 2,
    qpack_cmd_postbase_index = 3,
};

}  // namespace net
}  // namespace hotplace

#endif
