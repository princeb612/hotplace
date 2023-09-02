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

cbor_publisher::cbor_publisher ()
{
    // do nothing
}

return_t cbor_publisher::publish (cbor_object* object, binary_t* b)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == object || nullptr == b) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cbor_concise_visitor concise (b);
        object->accept (&concise);
    }
    __finally2
    {
        // do nothing
    }

    return ret;
}

return_t cbor_publisher::publish (cbor_object* object, stream_t* s)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == object || nullptr == s) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cbor_diagnostic_visitor diagnostic (s);
        object->accept (&diagnostic);
    }
    __finally2
    {
        // do nothing
    }

    return ret;
}

}
}