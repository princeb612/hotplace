/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/net/server/network_priority_queue.hpp>
#include <hotplace/sdk/net/server/network_session.hpp>
#include <hotplace/sdk/net/server/network_stream.hpp>

namespace hotplace {
namespace net {

network_priority_queue::network_priority_queue() {
    // do nothing
}

network_priority_queue::~network_priority_queue() {
    // do nothing
}

return_t network_priority_queue::push(int priority, network_session* token) {
    return_t ret = errorcode_t::success;

    ret = _mfq.push(priority, token);
    return ret;
}

return_t network_priority_queue::pop(int* priority, network_session** ptr_token) {
    return_t ret = errorcode_t::success;

    ret = _mfq.pop(priority, ptr_token, 1);
    return ret;
}

network_session* network_priority_queue::pop() {
    int priority = 0;
    network_session* session_object = nullptr;

    _mfq.pop(&priority, &session_object, 1);

    return session_object;
}

size_t network_priority_queue::size() { return _mfq.size(); }

}  // namespace net
}  // namespace hotplace
