/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   stream_policy.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2026.08.31   Soo Han, Kim        local_stream_policy
 *
 */

#include <ctype.h>

#include <hotplace/sdk/base/stream/stream_policy.hpp>

namespace hotplace {

const uint32 basic_stream_policy_minsize = 1 << 3;
const uint32 basic_stream_policy_allocsize = 1 << 7;

stream_policy stream_policy::_instance;

stream_policy::stream_policy() { _config.emplace("allocsize", basic_stream_policy_allocsize); }

stream_policy* stream_policy::get_instance() { return &_instance; }

stream_policy& stream_policy::set_allocsize(size_t allocsize) {
    if (allocsize < basic_stream_policy_minsize) {
        allocsize = basic_stream_policy_minsize;
    }
    auto pib = _config.emplace("allocsize", allocsize);
    if (false == pib.second) {
        pib.first->second = allocsize;
    }
    return *this;
}

size_t stream_policy::get_allocsize() { return _config["allocsize"]; }

local_stream_policy::local_stream_policy(size_t allocsize) { _allocsize = (basic_stream_policy_minsize < allocsize) ? allocsize : basic_stream_policy_minsize; }

size_t local_stream_policy::get_allocsize() const { return _allocsize; }

}  // namespace hotplace
