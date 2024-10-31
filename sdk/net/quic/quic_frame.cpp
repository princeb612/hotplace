/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/quic/quic.hpp>

namespace hotplace {
namespace net {

quick_frame::quick_frame() : _type(0) {}

quick_frame::quick_frame(quic_frame_t type) : _type(type) {}

quick_frame::quick_frame(const quick_frame& rhs) : _type(rhs._type) {}

}  // namespace net
}  // namespace hotplace
