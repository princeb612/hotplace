/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   network_protocol_group.cpp
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

network_protocol_group::network_protocol_group() { _shared.addref(); }

network_protocol_group::~network_protocol_group() { clear(); }

return_t network_protocol_group::add(network_protocol* protocol) {
    return_t ret = errorcode_t::success;

    if (nullptr == protocol) {
        return errorcode_t::invalid_parameter;
    }

    critical_section_guard guard(_lock);
    auto pib = _protocols.emplace(protocol->protocol_id(), protocol);
    if (true == pib.second) {
        protocol->addref();
    }

    return ret;
}

network_protocol_group& network_protocol_group::operator<<(network_protocol* protocol) {
    add(protocol);
    return *this;
}

return_t network_protocol_group::find(const std::string& protocol_id, network_protocol** ptr_protocol) {
    if (nullptr == ptr_protocol) {
        return errorcode_t::invalid_parameter;
    }

    critical_section_guard guard(_lock);
    auto iter = _protocols.find(protocol_id);
    if (_protocols.end() == iter) {
        return errorcode_t::not_found;
    } else {
        network_protocol* protocol = iter->second;
        protocol->addref();
        *ptr_protocol = protocol;
    }

    return errorcode_t::success;
}

network_protocol* network_protocol_group::operator[](const std::string& protocol_id) {
    network_protocol* protocol = nullptr;

    find(protocol_id, &protocol);
    return protocol;
}

return_t network_protocol_group::remove(network_protocol* protocol) {
    if (nullptr == protocol) {
        return errorcode_t::invalid_parameter;
    }

    critical_section_guard guard(_lock);
    auto iter = _protocols.find(protocol->protocol_id());
    if (_protocols.end() != iter) {
        network_protocol* protocol_ref = iter->second;
        protocol_ref->release();
    }

    return errorcode_t::success;
}

return_t network_protocol_group::clear() {
    critical_section_guard guard(_lock);
    for (auto& pair : _protocols) {
        network_protocol* protocol = pair.second;
        protocol->release();
    }
    _protocols.clear();

    return errorcode_t::success;
}

bool network_protocol_group::empty() { return _protocols.empty(); }

return_t network_protocol_group::is_kind_of(void* stream, size_t stream_size, network_protocol** ptr_protocol) {
    return_t ret = errorcode_t::success;
    network_protocol* protocol_match = nullptr;

    if (nullptr == ptr_protocol) {
        return errorcode_t::invalid_parameter;
    }

    critical_section_guard guard(_lock);

    for (auto& pair : _protocols) {
        network_protocol* protocol = pair.second;
        return_t test = protocol->is_kind_of(stream, stream_size);

        if (errorcode_t::success == test) {
            protocol_match = protocol;
            protocol_match->addref();
            break;
        } else if (errorcode_t::more_data == test) {
            ret = test;
            protocol_match = protocol;
        }
    }

    if (nullptr == protocol_match) {
        ret = errorcode_t::not_supported;
    }
    if (errorcode_t::success == ret) {
        *ptr_protocol = protocol_match;
    }

    return ret;
}

int network_protocol_group::addref() { return _shared.addref(); }

int network_protocol_group::release() { return _shared.delref(); }

}  // namespace net
}  // namespace hotplace
