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
#include <hotplace/sdk/crypto/basic/openssl_sign.hpp>
#include <hotplace/sdk/crypto/cose/cbor_object_signing.hpp>
#include <hotplace/sdk/io/cbor/cbor_array.hpp>
#include <hotplace/sdk/io/cbor/cbor_data.hpp>
#include <hotplace/sdk/io/cbor/cbor_encode.hpp>
#include <hotplace/sdk/io/cbor/cbor_map.hpp>
#include <hotplace/sdk/io/cbor/cbor_publisher.hpp>
#include <hotplace/sdk/io/cbor/cbor_reader.hpp>
#include <hotplace/sdk/io/cbor/concise_binary_object_representation.hpp>

namespace hotplace {
using namespace io;
namespace crypto {

cbor_object_signing::cbor_object_signing ()
{
    // do nothing
}

cbor_object_signing::~cbor_object_signing ()
{
    // do nothing
}

return_t cbor_object_signing::sign (cose_context_t* handle, crypto_key* key, cose_alg_t method, binary_t const& input, binary_t& output)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == handle || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        std::list<cose_alg_t> methods;
        methods.push_back (method);

        ret = sign (handle, key, methods, input, output);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing::sign (cose_context_t* handle, crypto_key* key, std::list<cose_alg_t> methods, binary_t const& input, binary_t& output)
{
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance ();

    __try2
    {
        if (nullptr == handle || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cbor_object_signing_encryption::clear_context (handle);

        handle->payload = input;

        cbor_tag_t tag = cbor_tag_t::cose_tag_sign;
        cbor_object_signing_encryption::composer composer;
        cbor_publisher pub;
        std::list<cose_alg_t>::iterator iter;
        for (iter = methods.begin (); iter != methods.end (); iter++) {
            cose_alg_t method = *iter;
            crypt_sig_t sig = advisor->cose_sigof (method);

            std::string kid;
            EVP_PKEY* pkey = key->select (kid, sig);
            // subitem of handle
            cose_parts_t item;
            // composer
            crypt_variant_t cvt;
            // create a binary using cbor_pushlisher and put it into subitem of handle
            cbor_data* cbor_sign_protected = nullptr;

            binary_t temp;

            // 1 protected (alg)
            // 1.1 compose
            variant_set_int16 (cvt.key, cose_header_t::cose_header_alg);
            variant_set_int16 (cvt.value, method);
            item.protected_list.push_back (cvt);
            composer.build_protected (&cbor_sign_protected, item.protected_list);
            // 1.2 bin_protected
            variant_binary (cbor_sign_protected->data (), item.bin_protected);
            
            // 2 unprotected (kid)
            if (kid.size ()) {
                // 2.1 compose
                variant_set_int16 (cvt.key, cose_header_t::cose_header_kid);
                variant_set_bstr_new (cvt.value, kid.c_str (), kid.size ());
                item.unprotected_list.push_back (cvt);
                // bin_unprotected is not a member of the tobesigned
            }

            binary_t tobesigned;
            compose_tobesigned (tobesigned, tag, convert (""), item.bin_protected, convert (""), input);
            openssl_sign signprocessor;
            signprocessor.sign (pkey, sig, tobesigned, item.bin_data); // signature

            handle->subitems.push_back (item);

            cbor_sign_protected->release ();

            switch (method) {
                case cose_alg_t::cose_hs256_64:
                    item.bin_data.resize (64 >> 3);
                    break;
                default:
                    break;
            }
        }

        ret = write_signature (handle, tag, output);
    }
    __finally2
    {
        // do nothing
    }

    return ret;
}

return_t finditem (int key, int& value, crypt_cosemap_t& from, crypt_cosemap_t& body)
{
    return_t ret = errorcode_t::success;
    crypt_cosemap_t::iterator iter;
    basic_stream cosekey;
    variant_t vt;

    variant_set_int16 (vt, key);
    vtprintf (&cosekey, vt);

    maphint <std::string, variant_t> hint (from);
    ret = hint.find (cosekey.c_str (), &vt);
    if (errorcode_t::success == ret) {
        value = t_variant_to_int<int> (vt);
    } else {
        maphint <std::string, variant_t> hint2 (body);
        ret = hint2.find (cosekey.c_str (), &vt);
        if (errorcode_t::success == ret) {
            value = t_variant_to_int<int> (vt);
        }
    }
    return ret;
}

return_t finditem (int key, std::string& value, crypt_cosemap_t& from, crypt_cosemap_t& body)
{
    return_t ret = errorcode_t::success;
    basic_stream cosekey;
    variant_t vt;

    variant_set_int16 (vt, key);
    vtprintf (&cosekey, vt);

    maphint <std::string, variant_t> hint (from);
    ret = hint.find (cosekey.c_str (), &vt);
    if (errorcode_t::success == ret) {
        variant_string (vt, value);
    } else {
        maphint <std::string, variant_t> hint2 (body);
        ret = hint2.find (cosekey.c_str (), &vt);
        if (errorcode_t::success == ret) {
            variant_string (vt, value);
        }
    }
    return ret;
}

return_t cbor_object_signing::verify (cose_context_t* handle, crypto_key* key, binary_t const& input, bool& result)
{
    return_t ret = errorcode_t::success;
    return_t check = errorcode_t::success;
    cbor_object_signing cose_sign;
    std::set <bool> results;

    __try2
    {
        ret = errorcode_t::verify;
        result = false;

        parse (handle, input);

        const char* k = nullptr;

        binary_t tobesigned;
        size_t size_subitems = handle->subitems.size ();
        std::list <cose_parts_t>::iterator iter;
        for (iter = handle->subitems.begin (); iter != handle->subitems.end (); iter++) {
            cose_parts_t& item = *iter;
            compose_tobesigned (tobesigned, handle->tag, handle->body.bin_protected, item.bin_protected, convert (""), handle->payload);
            int alg = 0;
            std::string kid;
            finditem (cose_header_t::cose_header_alg, alg, item.protected_map, handle->body.protected_map);
            finditem (cose_header_t::cose_header_kid, kid, item.unprotected_map, handle->body.unprotected_map);
            if (kid.size ()) {
                k = kid.c_str ();;
            }

            check = verify (handle, key, k, (cose_alg_t) alg, tobesigned, item.bin_data);
            results.insert ((errorcode_t::success == check) ? true : false);
        }

        if ((1 == results.size ()) && (true == *results.begin ())) {
            result = true;
            ret = errorcode_t::success;
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing::write_signature (cose_context_t* handle, uint8 tag, binary_t& signature)
{
    return_t ret = errorcode_t::success;
    cbor_publisher pub;
    cbor_object_signing_encryption::composer composer;
    cbor_map* cbor_body_unprotected = nullptr;

    composer.build_unprotected (&cbor_body_unprotected, handle->body.unprotected_list);

    cbor_array* root = new cbor_array ();
    root->tag (true, (cbor_tag_t) tag);
    *root << new cbor_data (handle->body.bin_protected)
          << cbor_body_unprotected
          << new cbor_data (handle->payload)
          << new cbor_array ();

    cbor_array* cbor_signatures = (cbor_array*) (*root)[3];
    std::list <cose_parts_t>::iterator iter;
    for (iter = handle->subitems.begin (); iter != handle->subitems.end (); iter++) {
        cose_parts_t& item = *iter;
        cbor_map* cbor_sign_unprotected = nullptr;

        composer.build_unprotected (&cbor_sign_unprotected, item.unprotected_list);

        cbor_array* cbor_signature = new cbor_array ();
        *cbor_signature << new cbor_data (item.bin_protected)
                        << cbor_sign_unprotected
                        << new cbor_data (item.bin_data);

        *cbor_signatures << cbor_signature;
    }

    pub.publish (root, &signature);

    root->release ();
    return ret;
}

return_t cbor_object_signing::verify (cose_context_t* handle, crypto_key* key, const char* kid, cose_alg_t alg, binary_t const& tobesigned, binary_t const& signature)
{
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance ();
    openssl_sign signprocessor;

    __try2
    {
        if (nullptr == handle || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        crypt_sig_t sig = advisor->cose_sigof (alg);
        EVP_PKEY* pkey = nullptr;
        if (kid) {
            pkey = key->find (kid, sig);
        } else {
            std::string k;
            pkey = key->select (k, sig);
        }

        switch (alg) {
            case cose_es256:
            case cose_es384:
            case cose_es512:
            case cose_ps256:
            case cose_ps384:
            case cose_ps512:
            case cose_rs256:
            case cose_rs384:
            case cose_rs512:
                ret = signprocessor.verify (pkey, sig, tobesigned, signature);
                break;
            default:
                ret = errorcode_t::request; // studying...
                break;
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing::parse (cose_context_t* handle, binary_t const& input)
{
    return_t ret = errorcode_t::success;
    return_t check = errorcode_t::success;
    cbor_reader reader;
    cbor_reader_context_t* reader_context = nullptr;
    cbor_object* root = nullptr;
    const char* kid = nullptr;
    std::set <bool> results;

    __try2
    {
        cbor_object_signing_encryption::clear_context (handle);

        ret = reader.open (&reader_context);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = reader.parse (reader_context, input);
        if (errorcode_t::success != ret) {
            __leave2_trace (ret);
        }
        ret = reader.publish (reader_context, &root);
        if (errorcode_t::success != ret) {
            __leave2_trace (ret);
        }

        if ((root->tagged ()) && (cbor_type_t::cbor_type_array == root->type ())) {
            // do nothing
        } else {
            ret = errorcode_t::request;
            __leave2_trace (ret);
        }

        if (4 != root->size ()) {
            ret = errorcode_t::bad_data;
            __leave2_trace (ret);
        }

        cbor_tag_t tag = root->tag_value ();
        switch (tag) {
            case cbor_tag_t::cose_tag_sign:
            case cbor_tag_t::cose_tag_sign1:
                break;
            default:
                ret = errorcode_t::request;
                break;
        }
        if (errorcode_t::success != ret) {
            __leave2_trace (ret);
        }
        handle->tag = tag;

        cbor_data* cbor_protected = (cbor_data*) (*(cbor_array*) root)[0];
        cbor_map* cbor_unprotected = (cbor_map*) (*(cbor_array*) root)[1];
        cbor_data* cbor_payload = (cbor_data*) (*(cbor_array*) root)[2];

        bool typecheck1 = (cbor_type_t::cbor_type_data == cbor_protected->type ());
        bool typecheck2 = (cbor_type_t::cbor_type_map == cbor_unprotected->type ());
        bool typecheck3 = (cbor_type_t::cbor_type_data == cbor_payload->type ());
        if (typecheck1 && typecheck2 && typecheck3) {
        } else {
            ret = errorcode_t::bad_data;
            __leave2_trace (ret);
        }

        binary_t bin_signer_signature;
        variant_binary (cbor_protected->data (), handle->body.bin_protected);
        variant_binary (cbor_payload->data (), handle->payload);
        parse_binary (handle->body.bin_protected, handle->body.protected_map);
        parse_map (cbor_unprotected, handle->body.unprotected_map);

        if (cbor_tag_t::cose_tag_sign == tag) {
            cbor_array* cbor_signatures = (cbor_array*) (*(cbor_array*) root)[3];

            size_t size_array = cbor_signatures->size ();
            for (size_t i = 0; i < size_array; i++) {
                cbor_array* cbor_signature = (cbor_array*) (*cbor_signatures)[i];
                if (3 == cbor_signature->size ()) {
                    cbor_data* cbor_signer_protected = (cbor_data*) (*cbor_signature)[0];
                    cbor_map* cbor_signer_unprotected = (cbor_map*) (*cbor_signature)[1];
                    cbor_data* cbor_signer_signature = (cbor_data*) (*cbor_signature)[2];

                    cose_parts_t part;
                    variant_binary (cbor_signer_protected->data (), part.bin_protected);
                    variant_binary (cbor_signer_signature->data (), part.bin_data);
                    parse_binary (part.bin_protected, part.protected_map);
                    parse_map (cbor_signer_unprotected, part.unprotected_map);
                    handle->subitems.push_back (part);
                }
            }
        } else if (cbor_tag_t::cose_tag_sign1 == tag) {
            cbor_data* cbor_signature = (cbor_data*) (*(cbor_array*) root)[3];

            cose_parts_t part;
            variant_binary (cbor_signature->data (), part.bin_data);
            handle->subitems.push_back (part);
        }
    }
    __finally2
    {
        reader.close (reader_context);

        if (root) {
            root->release ();
        }
    }
    return ret;
}

return_t cbor_object_signing::parse_binary (binary_t const& data, crypt_cosemap_t& vtl)
{
    return_t ret = errorcode_t::success;
    cbor_reader reader;
    cbor_reader_context_t* reader_context = nullptr;
    cbor_object* root = nullptr;

    __try2
    {
        ret = reader.open (&reader_context);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = reader.parse (reader_context, data);
        if (errorcode_t::success != ret) {
            __leave2; // bstr of length zero is used
        }
        ret = reader.publish (reader_context, &root);
        if (errorcode_t::success != ret) {
            __leave2_trace (ret);
        }

        if (cbor_type_t::cbor_type_map != root->type ()) {
            ret = errorcode_t::bad_data;
            __leave2_trace (ret);
        }

        ret = parse_map ((cbor_map*) root, vtl);
    }
    __finally2
    {
        reader.close (reader_context);

        if (root) {
            root->release ();
        }
    }
    return ret;
}

return_t cbor_object_signing::parse_map (cbor_map* root, crypt_cosemap_t& vtl)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        size_t size_map = root->size ();
        for (size_t i = 0; i < size_map; i++) {
            cbor_pair* pair = (*root)[i];
            cbor_data* key = (cbor_data*) pair->left ();
            cbor_object* value = (cbor_object*) pair->right ();
            if (cbor_type_t::cbor_type_data == value->type ()) {
                cbor_data* data = (cbor_data*) value;
                basic_stream cosekey;
                variant_t vt;
                vtprintf (&cosekey, key->data ());
                variant_copy (&vt, &data->data ());
                vtl.insert (std::make_pair (cosekey.c_str (), vt));
            }
        }
    }
    __finally2
    {
        // do nothing
    }

    return ret;
}

return_t cbor_object_signing::compose_tobesigned (binary_t& tobesigned, uint8 tag, binary_t const& body_protected, binary_t const& sign_protected, binary_t const& aad, binary_t const& payload)
{
    return_t ret = errorcode_t::success;
    cbor_encode encoder;
    cbor_publisher pub;
    cbor_array* root = nullptr;

    __try2
    {
        tobesigned.clear ();

        root = new cbor_array ();

        if (cbor_tag_t::cose_tag_sign == tag) {
            *root << new cbor_data ("Signature");
        } else if (cbor_tag_t::cose_tag_sign1 == tag) {
            *root << new cbor_data ("Signature1");
        } else {
            ret = errorcode_t::request;
        }

        *root << new cbor_data (body_protected);
        if (cbor_tag_t::cose_tag_sign == tag) {
            // This field is omitted for the COSE_Sign1 signature structure.
            *root << new cbor_data (sign_protected);
        }
        *root << new cbor_data (aad) << new cbor_data (payload);
        pub.publish (root, &tobesigned);
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
