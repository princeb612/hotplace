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

#include <hotplace/sdk/crypto/cose/cbor_object_signing.hpp>
#include <hotplace/sdk/crypto/cose/cbor_object_signing_encryption.hpp>
#include <hotplace/sdk/crypto/cose/cose_composer.hpp>
#include <hotplace/sdk/io/cbor/cbor_array.hpp>
#include <hotplace/sdk/io/cbor/cbor_data.hpp>
#include <hotplace/sdk/io/cbor/cbor_map.hpp>
#include <hotplace/sdk/io/cbor/cbor_publisher.hpp>
#include <hotplace/sdk/io/cbor/cbor_reader.hpp>
#include <hotplace/sdk/io/stream/buffer_stream.hpp>

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

        reset (handle);
        delete handle;
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

static void clear_cose_object_map (cose_object_map_t& object)
{
    cose_object_map_t::iterator iter;

    for (iter = object.begin (); iter != object.end (); iter++) {
        variant_t& item = iter->second;
        variant_free (item);
    }
    object.clear ();
}

return_t cbor_object_signing_encryption::reset (cose_context_t* handle)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        handle->sig = 0;
        handle->tag = 0;
        clear_cose_object_map (handle->object_map);
        cose_object_map_list_t::iterator iter;
        for (iter = handle->array.begin (); iter != handle->array.end (); iter++) {
            clear_cose_object_map (*iter);
        }
        handle->array.clear ();
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::sign (cose_context_t* handle, crypto_key* key, crypt_sig_t method, binary_t const& input, binary_t& output)
{
    return_t ret = errorcode_t::success;
    cbor_object_signing sign;

    binary_t bin_signature;

    ret = sign.sign (handle, key, method, input, bin_signature);
    if (errorcode_t::success == ret) {
        std::string kid (handle->kid);
        cose_composer composer;

        cbor_data* cbor_data_protected = nullptr;
        composer.build_protected (&cbor_data_protected);

        cbor_data* cbor_data_payload = nullptr;
        composer.build_data (&cbor_data_payload, input);

        cbor_array* root = nullptr;
        root = new cbor_array ();
        root->tag (true, cbor_tag_t::cose_tag_sign);
        *root   << cbor_data_protected  // protected, bstr
                << new cbor_map ()      // unprotected, map
                << cbor_data_payload    // payload, bstr/nil(detached)
                << new cbor_array ();   // signatures

        cbor_array* signatures = (cbor_array*) (*root)[3];

        cbor_array* signature = new cbor_array ();
        {
            cbor_data* cbor_data_signature_protected = nullptr;
            {
                cose_item_t item;
                cose_list_t list_protected;
                variant_set_int16 (item.key, cose_header_t::cose_header_alg);
                variant_set_int16 (item.value, cose_alg_t::cose_es512); // todo - type conversion
                list_protected.push_back (item);
                composer.build_protected (&cbor_data_signature_protected, list_protected);
            }

            cbor_map* cbor_data_signature_unprotected = nullptr;
            {
                cose_item_t item;
                cose_list_t list_unprotected;
                variant_set_int16 (item.key, cose_header_t::cose_header_kid);
                variant_set_bstr_new (item.value, kid.c_str (), kid.size ());
                list_unprotected.push_back (item);
                composer.build_unprotected (&cbor_data_signature_unprotected, list_unprotected);
            }

            cbor_data* cbor_data_signature_signature = nullptr;
            {
                composer.build_data (&cbor_data_signature_signature, bin_signature);
            }

            *signature  << cbor_data_signature_protected
                        << cbor_data_signature_unprotected
                        << cbor_data_signature_signature;
        }
        *signatures << signature;

        cbor_publisher publisher;
        publisher.publish (root, &output);

        root->release ();
    }

    return ret;
}

return_t cbor_object_signing_encryption::sign (cose_context_t* handle, crypto_key* key, crypt_sig_t method, binary_t const& input, binary_t& output, std::string& kid)
{
    return_t ret = errorcode_t::success;
    cbor_object_signing sign;

    ret = sign.sign (handle, key, method, input, output, kid);
    return ret;
}

return_t cbor_object_signing_encryption::verify (cose_context_t* handle, crypto_key* key, crypt_sig_t method, binary_t const& input, binary_t const& output, bool& result)
{
    return_t ret = errorcode_t::success;
    cbor_object_signing sign;

    ret = sign.verify (handle, key, method, input, output, result);
    return ret;
}

return_t cbor_object_signing_encryption::verify (cose_context_t* handle, crypto_key* key, const char* kid, crypt_sig_t method, binary_t const& input, binary_t const& output, bool& result)
{
    return_t ret = errorcode_t::success;
    cbor_object_signing sign;

    ret = sign.verify (handle, key, kid, method, input, output, result);
    return ret;
}

}
}  // namespace
