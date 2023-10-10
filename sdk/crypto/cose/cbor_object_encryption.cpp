/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include <hotplace/sdk/crypto/cose/cbor_object_encryption.hpp>
#include <hotplace/sdk/io/cbor/cbor_array.hpp>
#include <hotplace/sdk/io/cbor/cbor_data.hpp>
#include <hotplace/sdk/io/cbor/cbor_map.hpp>
#include <hotplace/sdk/io/cbor/cbor_publisher.hpp>
#include <hotplace/sdk/io/cbor/cbor_reader.hpp>

namespace hotplace {
namespace crypto {

cbor_object_encryption::cbor_object_encryption ()
{
    // do nothing
}

cbor_object_encryption::~cbor_object_encryption ()
{
    // do nothing
}

return_t cbor_object_encryption::encrypt (cose_context_t* handle, crypto_key* key, cose_alg_t method, binary_t const& input, binary_t& output)
{
    return_t ret = errorcode_t::success;

    return ret;
}

return_t cbor_object_encryption::encrypt (cose_context_t* handle, crypto_key* key, std::list<cose_alg_t> methods, binary_t const& input, binary_t& output)
{
    return_t ret = errorcode_t::success;

    return ret;
}

return_t cbor_object_encryption::decrypt (cose_context_t* handle, crypto_key* key, binary_t const& input, bool& result)
{
    return_t ret = errorcode_t::success;

    return ret;
}

}
}  // namespace
