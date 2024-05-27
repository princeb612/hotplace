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

hpack::hpack() : _encoder(nullptr), _session(nullptr), _flags(hpack_indexing | hpack_huffman) {}

hpack::~hpack() {}

hpack& hpack::set_encoder(hpack_encoder* hp) {
    _encoder = hp;
    return *this;
}

hpack& hpack::set_session(hpack_session* session) {
    _session = session;
    return *this;
}

hpack_encoder* hpack::get_encoder() { return _encoder; }

hpack_session* hpack::get_session() { return _session; }

hpack& hpack::set_encode_flags(uint32 flags) {
    _flags = flags;
    return *this;
}

hpack& hpack::encode_header(const std::string& name, const std::string& value, uint32 flags) {
    if (_session) {
        (*_encoder).encode_header(_session, _bin, name, value, flags ? flags : _flags);
    }
    return *this;
}

hpack& hpack::decode_header(const byte_t* source, size_t size, size_t& pos, std::string& name, std::string& value) {
    if (_session) {
        (*_encoder).decode_header(_session, source, size, pos, name, value);
    }
    return *this;
}

binary_t& hpack::get_binary() { return _bin; }

}  // namespace net
}  // namespace hotplace
