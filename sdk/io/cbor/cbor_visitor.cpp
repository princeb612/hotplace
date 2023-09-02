/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2023.09.01   Soo Han, Kim        refactor
 */

#include <hotplace/sdk/io/cbor/cbor.hpp>

namespace hotplace {
namespace io {

cbor_concise_visitor::cbor_concise_visitor (binary_t* concise) : _concise (concise)
{
    if (nullptr == concise) {
        throw errorcode_t::invalid_parameter;
    }
}

cbor_concise_visitor::~cbor_concise_visitor ()
{
    // do nothing
}

return_t cbor_concise_visitor::visit (cbor_object* object)
{
    return_t ret = errorcode_t::success;

    object->represent (get_binary ());
    return ret;
}

return_t cbor_concise_visitor::visit (cbor_data* object)
{
    return_t ret = errorcode_t::success;

    object->represent (get_binary ());
    return ret;
}

return_t cbor_concise_visitor::visit (cbor_bstrings* object)
{
    return_t ret = errorcode_t::success;

    object->represent (get_binary ());
    return ret;
}

return_t cbor_concise_visitor::visit (cbor_tstrings* object)
{
    return_t ret = errorcode_t::success;

    object->represent (get_binary ());
    return ret;
}

return_t cbor_concise_visitor::visit (cbor_pair* object)
{
    return_t ret = errorcode_t::success;

    object->represent (get_binary ());
    return ret;
}

return_t cbor_concise_visitor::visit (cbor_map* object)
{
    return_t ret = errorcode_t::success;

    object->represent (get_binary ());
    return ret;
}

return_t cbor_concise_visitor::visit (cbor_array* object)
{
    return_t ret = errorcode_t::success;

    object->represent (get_binary ());
    return ret;
}

binary_t* cbor_concise_visitor::get_binary ()
{
    return _concise;
}

cbor_diagnostic_visitor::cbor_diagnostic_visitor (stream_t* stream) : _diagnostic (stream)
{
    if (nullptr == stream) {
        throw errorcode_t::invalid_parameter;
    }
}

cbor_diagnostic_visitor::~cbor_diagnostic_visitor ()
{
    // do nothing
}

return_t cbor_diagnostic_visitor::visit (cbor_object* object)
{
    return_t ret = errorcode_t::success;

    object->represent (get_stream ());
    return ret;
}

return_t cbor_diagnostic_visitor::visit (cbor_data* object)
{
    return_t ret = errorcode_t::success;

    object->represent (get_stream ());
    return ret;
}

return_t cbor_diagnostic_visitor::visit (cbor_bstrings* object)
{
    return_t ret = errorcode_t::success;

    object->represent (get_stream ());
    return ret;
}

return_t cbor_diagnostic_visitor::visit (cbor_tstrings* object)
{
    return_t ret = errorcode_t::success;

    object->represent (get_stream ());
    return ret;
}

return_t cbor_diagnostic_visitor::visit (cbor_pair* object)
{
    return_t ret = errorcode_t::success;

    object->represent (get_stream ());
    return ret;
}

return_t cbor_diagnostic_visitor::visit (cbor_map* object)
{
    return_t ret = errorcode_t::success;

    object->represent (get_stream ());
    return ret;
}

return_t cbor_diagnostic_visitor::visit (cbor_array* object)
{
    return_t ret = errorcode_t::success;

    object->represent (get_stream ());
    return ret;
}

stream_t* cbor_diagnostic_visitor::get_stream ()
{
    return _diagnostic;
}

}
}
