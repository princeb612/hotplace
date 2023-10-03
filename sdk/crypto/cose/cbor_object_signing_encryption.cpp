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

#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/cose/cbor_object_signing.hpp>
#include <hotplace/sdk/crypto/cose/cbor_object_signing_encryption.hpp>
#include <hotplace/sdk/crypto/cose/cose_composer.hpp>
#include <hotplace/sdk/io/cbor/cbor_array.hpp>
#include <hotplace/sdk/io/cbor/cbor_data.hpp>
#include <hotplace/sdk/io/cbor/cbor_map.hpp>
#include <hotplace/sdk/io/cbor/cbor_publisher.hpp>
#include <hotplace/sdk/io/cbor/cbor_reader.hpp>
#include <hotplace/sdk/io/stream/buffer_stream.hpp>
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

static void clear_cose_contents_list (cose_conents_list_t& object)
{
    cose_conents_list_t::iterator iter;

    for (iter = object.begin (); iter != object.end (); iter++) {
        cose_conents_t& item = *iter;
        clear_cose_object_map (item.protected_map);
        clear_cose_object_map (item.unprotected_map);
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

    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::sign (cose_context_t* handle, crypto_key* key, cose_alg_t method, binary_t const& input, binary_t& output)
{
    return_t ret = errorcode_t::success;
    return_t check = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance ();
    cbor_object_signing sign;
    cose_composer composer;

    crypt_sig_t sig = advisor->cose_sigof (method);
    binary_t bin_signature;
    std::string kid;

    __try2
    {
        if (nullptr == handle || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = sign.sign (handle, key, method, input, bin_signature, kid);
        if (errorcode_t::success != ret) {
            __leave2;
        }

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
                variant_set_int16 (item.value, method);
                list_protected.push_back (item);
                composer.build_protected (&cbor_data_signature_protected, list_protected);
            }

            cbor_map* cbor_data_signature_unprotected = nullptr;
            {
                cose_list_t list_unprotected;
                if (kid.size ()) {
                    cose_item_t item;
                    variant_set_int16 (item.key, cose_header_t::cose_header_kid);
                    variant_set_bstr_new (item.value, kid.c_str (), kid.size ());
                    list_unprotected.push_back (item);
                }
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
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t read_cbor_data (binary_t& bin, cbor_data* node)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        bin.clear ();

        if (nullptr == node) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const variant_t& data = node->data ();
        if (TYPE_BINARY == data.type) {
            variant_binary (data, bin);
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t read_cbor_map (cose_object_map_t& target, cbor_map* source)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == source) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        std::list <cbor_pair*> const& pairs = source->accessor ();
        std::list <cbor_pair*>::const_iterator iter;
        for (iter = pairs.begin (); iter != pairs.end (); iter++) {
            cbor_pair* pair = *iter;
            const variant_t& key = pair->left ()->data ();
            cbor_object* value = pair->right ();

            uint32 id = t_variant_to_int<uint32> (key);

            if (cbor_type_t::cbor_type_data == value->type ()) {
                variant_t item;
                variant_copy (&item, &((cbor_data*) value)->data ());
                target.insert (std::make_pair (id, item));
            }
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t parse_protected (cose_object_map_t& target, cbor_data* cbor_protected)
{
    return_t ret = errorcode_t::success;
    cbor_object* root = nullptr;

    __try2
    {
        if (nullptr == cbor_protected) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        binary_t bin_protected;
        read_cbor_data (bin_protected, cbor_protected);

        cbor_reader_context_t* reader_context = nullptr;
        cbor_reader reader;
        reader.open (&reader_context);
        reader.parse (reader_context, bin_protected);
        reader.publish (reader_context, &root);
        reader.close (reader_context);

        if (root && cbor_type_t::cbor_type_map == root->type ()) {
            read_cbor_map (target, (cbor_map*) root);
        }
    }
    __finally2
    {
        if (root) {
            root->release ();
        }
    }
    return ret;
}

return_t parse_unprotected (cose_object_map_t& target, cbor_map* cbor_unprotected)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == cbor_unprotected) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        read_cbor_map (target, cbor_unprotected);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t parse_signatures (cose_conents_list_t& target, cbor_array* cbor_signatures)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == cbor_signatures) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        size_t size_signatures = cbor_signatures->size ();
        for (size_t i = 0; i < size_signatures; i++) {
            cbor_array* cbor_signature = (cbor_array*) (*cbor_signatures) [i];
            cbor_data* cbor_sigprotected = (cbor_data*) (*cbor_signature)[0];
            cbor_map* cbor_sigunprotected = (cbor_map*) (*cbor_signature)[1];
            cbor_data* cbor_sigsignature = (cbor_data*) (*cbor_signature)[2];

            cose_conents_t contents;

            parse_protected (contents.protected_map, cbor_sigprotected);
            parse_unprotected (contents.unprotected_map, cbor_sigunprotected);
            read_cbor_data (contents.data, cbor_sigsignature);

            target.push_back (contents);
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

static return_t cose_verify (cose_context_t* handle, crypto_key* key, cose_object_map_t& protected_map, cose_object_map_t& unprotected_map, binary_t const& payload, binary_t const& signature)
{
    return_t ret = errorcode_t::success;
    return_t check = errorcode_t::success;
    cbor_object_signing cose_sign;
    bool result = false;
    variant_t item;
    const char* kid = nullptr;

    maphint <uint32, variant_t> hint_protected (protected_map);
    maphint <uint32, variant_t> hint_unprotected (unprotected_map);

    uint32 alg = 0;

    check = hint_protected.find (cose_header_t::cose_header_alg, &item);
    if (errorcode_t::success == check) {
        alg = t_variant_to_int<uint32> (item);
    }
    std::string string_kid;
    check = hint_unprotected.find (cose_header_t::cose_header_kid, &item);
    if (errorcode_t::success == check) {
        variant_string (item, string_kid);
        if (string_kid.size ()) {
            kid = string_kid.c_str ();
        }
    }

    ret = cose_sign.verify (handle, key, kid, (cose_alg_t) alg, payload, signature, result);

    return ret;
}

return_t cbor_object_signing_encryption::verify (cose_context_t* handle, crypto_key* key, binary_t const& input, bool& result)
{
    return_t ret = errorcode_t::success;
    return_t check = errorcode_t::success;
    //crypto_advisor* advisor = crypto_advisor::get_instance ();
    cbor_object_signing cose_sign;
    cbor_reader reader;
    cbor_reader_context_t* reader_context = nullptr;
    cbor_object* root = nullptr;
    binary_t payload;
    //std::string kid;
    const char* kid = nullptr;
    std::set <bool> results;

    __try2
    {
        ret = errorcode_t::verify;
        result = false;

        // applied pattern(s)
        // 1.1. Single Signature
        // 1.2. Multiple Signers
        // 2.1 Single ECDSA Signature

        reader.open (&reader_context);
        reader.parse (reader_context, input);
        reader.publish (reader_context, &root);
        reader.close (reader_context);

        //if (root->tagged () && cbor_type_t::cbor_type_array == root->type ()) {

        if ((root->tagged ()) && (cbor_type_t::cbor_type_array == root->type ())) {
            // do nothing
        } else {
            ret = errorcode_t::request;
            throw ret;
            __leave2;
        }

        cbor_data* cbor_payload = (cbor_data*) (*(cbor_array*) root)[2];
        read_cbor_data (payload, cbor_payload);

        if (cbor_tag_t::cose_tag_sign == root->tag_value ()) {
            cbor_array* cbor_signatures = (cbor_array*) (*(cbor_array*) root)[3];

            cose_conents_list_t contents_list;
            parse_signatures (contents_list, cbor_signatures);

            cose_conents_list_t::iterator iter;
            for (iter = contents_list.begin (); iter != contents_list.end (); iter++) {
                cose_conents_t& content = *iter;

                check = cose_verify (handle, key, content.protected_map, content.unprotected_map, payload, content.data);
                results.insert ((errorcode_t::success == check) ? true : false);
            }
        } else if (cbor_tag_t::cose_tag_sign1 == root->tag_value ()) {
            cbor_data* cbor_protected = (cbor_data*) (*(cbor_array*) root)[0];
            cbor_map* cbor_unprotected = (cbor_map*) (*(cbor_array*) root)[1];
            cbor_data* cbor_signature = (cbor_data*) (*(cbor_array*) root)[3];

            cose_object_map_t protected_map;
            cose_object_map_t unprotected_map;
            parse_protected (protected_map, cbor_protected);
            parse_unprotected (unprotected_map, cbor_unprotected);

            binary_t signature;
            read_cbor_data (signature, cbor_signature);

            check = cose_verify (handle, key, protected_map, unprotected_map, payload, signature);
            results.insert ((errorcode_t::success == check) ? true : false);
        }

        if ((1 == results.size ()) && (true == *results.begin ())) {
            result = true;
            ret = errorcode_t::success;
        }
    }
    __finally2
    {
        if (root) {
            root->release ();
        }
    }
    return ret;
}

}
}  // namespace
