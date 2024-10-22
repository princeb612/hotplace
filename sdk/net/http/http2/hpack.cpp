/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/http/http2/hpack.hpp>
#include <sdk/net/http/http_resource.hpp>

namespace hotplace {
namespace net {

hpack_stream::hpack_stream() : _session(nullptr), _flags(hpack_indexing | hpack_huffman) {}

hpack_stream::~hpack_stream() {}

hpack_stream& hpack_stream::set_session(hpack_session* session) {
    _session = session;
    return *this;
}

hpack_session* hpack_stream::get_session() { return _session; }

hpack_stream& hpack_stream::set_encode_flags(uint32 flags) {
    _flags = flags;
    return *this;
}

hpack_stream& hpack_stream::encode_header(const std::string& name, const std::string& value, uint32 flags) {
    if (_session) {
        hpack_encoder encoder;
        encoder.encode_header(_session, _bin, name, value, flags ? flags : _flags);
    }
    return *this;
}

hpack_stream& hpack_stream::decode_header(const byte_t* source, size_t size, size_t& pos, std::string& name, std::string& value) {
    if (_session) {
        hpack_encoder encoder;
        encoder.decode_header(_session, source, size, pos, name, value);
    }
    return *this;
}

binary_t& hpack_stream::get_binary() { return _bin; }

}  // namespace net
}  // namespace hotplace
