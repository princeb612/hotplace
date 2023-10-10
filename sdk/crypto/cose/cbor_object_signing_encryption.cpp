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

#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/cose/cbor_object_encryption.hpp>
#include <hotplace/sdk/crypto/cose/cbor_object_signing.hpp>
#include <hotplace/sdk/crypto/cose/cbor_object_signing_encryption.hpp>
#include <hotplace/sdk/io/cbor/cbor_array.hpp>
#include <hotplace/sdk/io/cbor/cbor_data.hpp>
#include <hotplace/sdk/io/cbor/cbor_encode.hpp>
#include <hotplace/sdk/io/cbor/cbor_map.hpp>
#include <hotplace/sdk/io/cbor/cbor_publisher.hpp>
#include <hotplace/sdk/io/cbor/cbor_reader.hpp>
#include <hotplace/sdk/io/cbor/concise_binary_object_representation.hpp>
#include <set>

namespace hotplace {
using namespace io;
namespace crypto {

cbor_object_signing_encryption::cbor_object_signing_encryption ()
{
    // do nothing
}

cbor_object_signing_encryption::~cbor_object_signing_encryption ()
{
    // do nothing
}

return_t cbor_object_signing_encryption::open (cose_context_t** handle)
{
    return_t ret = errorcode_t::success;
    cose_context_t* context = nullptr;

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        __try_new_catch (context, new cose_context_t, ret, __leave2);
        *handle = context;
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::close (cose_context_t* handle)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        clear_context (handle);
        delete handle;
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::encrypt (cose_context_t* handle, crypto_key* key, cose_alg_t method, binary_t const& input, binary_t& output)
{
    return_t ret = errorcode_t::success;
    cbor_object_encryption cose_encryption;

    ret = cose_encryption.encrypt (handle, key, method, input, output);
    return ret;
}

return_t encrypt (cose_context_t* handle, crypto_key* key, std::list<cose_alg_t> methods, binary_t const& input, binary_t& output)
{
    return_t ret = errorcode_t::success;
    cbor_object_encryption cose_encryption;

    ret = cose_encryption.encrypt (handle, key, methods, input, output);
    return ret;
}

return_t cbor_object_signing_encryption::decrypt (cose_context_t* handle, crypto_key* key, binary_t const& input, bool& result)
{
    return_t ret = errorcode_t::success;
    cbor_object_encryption cose_encryption;

    ret = cose_encryption.decrypt (handle, key, input, result);
    return ret;
}

return_t cbor_object_signing_encryption::sign (cose_context_t* handle, crypto_key* key, cose_alg_t method, binary_t const& input, binary_t& output)
{
    return_t ret = errorcode_t::success;
    cbor_object_signing cose_sign;

    ret = cose_sign.sign (handle, key, method, input, output);
    return ret;
}

return_t cbor_object_signing_encryption::sign (cose_context_t* handle, crypto_key* key, std::list<cose_alg_t> methods, binary_t const& input, binary_t& output)
{
    return_t ret = errorcode_t::success;
    cbor_object_signing cose_sign;

    ret = cose_sign.sign (handle, key, methods, input, output);
    return ret;
}

return_t cbor_object_signing_encryption::verify (cose_context_t* handle, crypto_key* key, binary_t const& input, bool& result)
{
    return_t ret = errorcode_t::success;
    cbor_object_signing cose_sign;

    ret = cose_sign.verify (handle, key, input, result);
    return ret;
}

return_t cbor_object_signing_encryption::clear_context (cose_context_t* handle)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        handle->tag = 0;
        handle->body.clear ();
        handle->payload.clear ();
        std::list <cose_parts_t>::iterator iter;
        for (iter = handle->subitems.begin (); iter != handle->subitems.end (); iter++) {
            cose_parts_t& item = *iter;
            item.clear ();
        }
        handle->subitems.clear ();
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

cbor_object_signing_encryption::composer::composer ()
{
    // do nothing
}
cbor_object_signing_encryption::composer::~composer ()
{
    // do nothing
}

return_t cbor_object_signing_encryption::composer::build_protected (cbor_data** object)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cbor_data* part_protected = nullptr;
        binary_t dummy;
        __try_new_catch (part_protected, new cbor_data (dummy), ret, __leave2);
        *object = part_protected;
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::composer::build_protected (cbor_data** object, crypt_variantlist_t& input)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (0 == input.size ()) {
            cbor_data* part_protected = nullptr;
            binary_t dummy;
            __try_new_catch (part_protected, new cbor_data (dummy), ret, __leave2);
            *object = part_protected;
        } else {
            binary_t bin_protected;
            cbor_map* part_protected = nullptr;

            __try_new_catch (part_protected, new cbor_map (), ret, __leave2);

            crypt_variantlist_t::iterator iter;
            for (iter = input.begin (); iter != input.end (); iter++) {
                crypt_variant_t& item = *iter;
                *part_protected << new cbor_pair (new cbor_data (item.key), new cbor_data (item.value));
            }

            build_protected (object, part_protected);

            part_protected->release ();
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::composer::build_protected (cbor_data** object, cbor_map* input)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == object || nullptr == input) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        binary_t bin_protected;
        cbor_publisher publisher;
        publisher.publish (input, &bin_protected);

        *object = new cbor_data (bin_protected);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::composer::build_unprotected (cbor_map** object)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cbor_map* part_unprotected = nullptr;

        __try_new_catch (part_unprotected, new cbor_map (), ret, __leave2);

        *object = part_unprotected;
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::composer::build_unprotected (cbor_map** object, crypt_variantlist_t& input)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cbor_map* part_unprotected = nullptr;

        __try_new_catch (part_unprotected, new cbor_map (), ret, __leave2);

        crypt_variantlist_t::iterator iter;
        for (iter = input.begin (); iter != input.end (); iter++) {
            crypt_variant_t& item = *iter;
            *part_unprotected << new cbor_pair (new cbor_data (item.key), new cbor_data (item.value));
        }

        *object = part_unprotected;
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::composer::build_data (cbor_data** object, const char* payload)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == object || nullptr == payload) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        __try_new_catch (*object, new cbor_data (convert (payload)), ret, __leave2);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::composer::build_data (cbor_data** object, const byte_t* payload, size_t size)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        __try_new_catch (*object, new cbor_data (payload, size), ret, __leave2);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::composer::build_data (cbor_data** object, binary_t const& payload)
{
    return build_data (object, &payload[0], payload.size ());
}

return_t cbor_object_signing_encryption::composer::build_data_b16 (cbor_data** object, const char* str)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == object || nullptr == str) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        __try_new_catch (*object, new cbor_data (base16_decode (str)), ret, __leave2);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

}
}  // namespace
