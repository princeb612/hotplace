/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/net/server/network_protocol.hpp>

namespace hotplace {
namespace net {

network_protocol_group::network_protocol_group ()
{
    _shared.addref ();
}

network_protocol_group::~network_protocol_group ()
{
    clear ();
}

return_t network_protocol_group::add (network_protocol* protocol)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == protocol) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        _lock.enter ();
        protocol_map_pib_t pib = _protocols.insert (std::make_pair (protocol->protocol_id (), protocol));
        if (true == pib.second) {
            protocol->addref ();
        }
        _lock.leave ();
    }
    __finally2
    {
        // do nothing
    }

    return ret;
}

network_protocol_group& network_protocol_group::operator << (network_protocol* protocol)
{
    add (protocol);
    return *this;
}

return_t network_protocol_group::find (uint32 protocol_id, network_protocol** ptr_protocol)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == ptr_protocol) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        _lock.enter ();
        protocol_map_t::iterator iter = _protocols.find (protocol_id);
        if (_protocols.end () == iter) {
            ret = errorcode_t::not_found;
        } else {
            network_protocol* protocol = iter->second;
            protocol->addref ();
            *ptr_protocol = protocol;
        }
        _lock.leave ();
    }
    __finally2
    {
        // do nothing
    }

    return ret;
}

network_protocol* network_protocol_group::operator[] (uint32 protocol_id)
{
    network_protocol* protocol = nullptr;

    find (protocol_id, &protocol);
    return protocol;
}

return_t network_protocol_group::remove (network_protocol* protocol)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == protocol) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        _lock.enter ();
        protocol_map_t::iterator iter = _protocols.find (protocol->protocol_id ());
        if (_protocols.end () != iter) {
            network_protocol* protocol_ref = iter->second;
            protocol_ref->release ();
        }
        _lock.leave ();
    }
    __finally2
    {
        // do nothing
    }

    return ret;
}

return_t network_protocol_group::clear ()
{
    return_t ret = errorcode_t::success;

    __try2
    {
        _lock.enter ();
        for (protocol_map_t::iterator it = _protocols.begin (); it != _protocols.end (); it++) {
            network_protocol* protocol_ref = it->second;

            protocol_ref->release ();
        }
        _protocols.clear ();
        _lock.leave ();
    }
    __finally2
    {
        // do nothing
    }

    return ret;
}

bool network_protocol_group::empty ()
{
    bool ret = _protocols.empty ();

    return ret;
}

return_t network_protocol_group::is_kind_of (void* stream, size_t stream_size, network_protocol** ptr_protocol)
{
    return_t ret = errorcode_t::success;
    network_protocol* protocol_match = nullptr;

    __try2
    {
        if (nullptr == ptr_protocol) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        _lock.enter ();
        for (protocol_map_t::iterator it = _protocols.begin (); it != _protocols.end (); it++) {
            network_protocol* protocol = it->second;
            return_t dwResult = protocol->is_kind_of (stream, stream_size);

            if (errorcode_t::success == dwResult) {
                protocol_match = protocol;
                protocol_match->addref ();
                break;
            } else if (errorcode_t::more_data == dwResult) {
                ret = dwResult;
                protocol_match = protocol;
            }
        }
        _lock.leave ();

        if (nullptr == protocol_match) {
            ret = errorcode_t::not_supported;
        }
        if (errorcode_t::success == ret) {
            *ptr_protocol = protocol_match;
        }
    }
    __finally2
    {
        // do nothing
    }

    return ret;
}

int network_protocol_group::addref ()
{
    return _shared.addref ();
}

int network_protocol_group::release ()
{
    return _shared.delref ();
}

}
}  // namespace
