/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/net/server/network_protocol.hpp>

namespace hotplace {
namespace net {

network_protocol::network_protocol() {
    _shared.make_share(this);
    _constraints.resize(protocol_constraints_t::protocol_constraints_the_end);
}

network_protocol::~network_protocol() {}

return_t network_protocol::is_kind_of(void* stream, size_t stream_size) { return errorcode_t::success; }

return_t network_protocol::read_stream(basic_stream* stream, size_t* request_size, protocol_state_t* state, int* priority) {
    *state = protocol_state_t::protocol_state_complete;
    return errorcode_t::success;
}

return_t network_protocol::set_constraints(protocol_constraints_t id, size_t value) {
    return_t ret = errorcode_t::success;
    if (id < protocol_constraints_t::protocol_constraints_the_end) {
        _constraints[id] = value;
    } else {
        ret = errorcode_t::invalid_request;
    }
    return ret;
}

size_t network_protocol::get_constraints(protocol_constraints_t id) {
    size_t ret_value = 0;
    if (id < protocol_constraints_t::protocol_constraints_the_end) {
        ret_value = _constraints[id];
    }
    return ret_value;
}

bool network_protocol::use_alpn() { return false; }

int network_protocol::addref() { return _shared.addref(); }

int network_protocol::release() { return _shared.delref(); }

}  // namespace net
}  // namespace hotplace
