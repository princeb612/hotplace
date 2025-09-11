/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/net/tls/quic/types.hpp>
#include <sdk/net/tls/quic_streams.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/types.hpp>

namespace hotplace {
namespace net {

quic_streams::quic_streams() : t_binaries<uint64, uint8>() {}

return_t quic_streams::set_unistream_type(uint64 stream_id, uint8 type) { return set_tag(stream_id, type); }

return_t quic_streams::get_unistream_type(uint64 stream_id, uint8& type) { return get_tag(stream_id, type); }

bool quic_streams::is_unidirectional_stream(uint64 stream_id) { return (quic_stream_unidirectional == (stream_id & quic_stream_unidirectional)); }

}  // namespace net
}  // namespace hotplace
