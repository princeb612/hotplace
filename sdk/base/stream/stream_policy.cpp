/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <ctype.h>

#include <sdk/base/stream/basic_stream.hpp>

namespace hotplace {

const uint32 basic_stream_policy_minsize = 1 << 3;
const uint32 basic_stream_policy_allocsize = 1 << 12;

stream_policy stream_policy::_instance;

stream_policy::stream_policy() { _config.insert(std::make_pair("allocsize", basic_stream_policy_allocsize)); }

stream_policy* stream_policy::get_instance() { return &_instance; }

stream_policy& stream_policy::set_allocsize(size_t allocsize) {
    if (allocsize < basic_stream_policy_minsize) {
        allocsize = basic_stream_policy_minsize;
    }
    std::pair<basic_stream_policy_map_t::iterator, bool> pib = _config.insert(std::make_pair("allocsize", allocsize));
    if (false == pib.second) {
        pib.first->second = allocsize;
    }
    return *this;
}

size_t stream_policy::get_allocsize() { return _config["allocsize"]; }

}  // namespace hotplace
