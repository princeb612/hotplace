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

cbor_object_signing::cbor_object_signing() {
    // do nothing
}

cbor_object_signing::~cbor_object_signing() {
    // do nothing
}

return_t cbor_object_signing::sign(cose_context_t* handle, crypto_key* key, cose_alg_t method, binary_t const& input, binary_t& output) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        std::list<cose_alg_t> methods;
        methods.push_back(method);

        ret = sign(handle, key, methods, input, output);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing::sign(cose_context_t* handle, crypto_key* key, std::list<cose_alg_t> methods, binary_t const& input, binary_t& output) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        cbor_object_signing_encryption::clear_context(handle);

        if (nullptr == handle || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        handle->payload = input;

        cbor_tag_t tag = cbor_tag_t::cose_tag_sign;
        cbor_object_signing_encryption::composer composer;
        cbor_publisher pub;
        std::list<cose_alg_t>::iterator iter;

        maphint<cose_param_t, binary_t> hint(handle->binarymap);
        binary_t external;
        hint.find(cose_param_t::cose_external, &external);

        for (iter = methods.begin(); iter != methods.end(); iter++) {
            cose_alg_t method = *iter;
            crypt_sig_t sig = advisor->cose_sigof(method);

            std::string kid;
            EVP_PKEY* pkey = key->select(kid, sig);
            // subitem of handle
            cose_parts_t item;
            // composer
            // create a binary using cbor_pushlisher and put it into subitem of handle
            cbor_data* cbor_sign_protected = nullptr;

            binary_t temp;

            // 1 protected (alg)
            // 1.1 compose
            variant_t value;
            variant_set_int16(value, method);
            item.protected_map.insert(std::make_pair(cose_key_t::cose_alg, value));
            composer.build_protected(&cbor_sign_protected, item.protected_map);
            // 1.2 bin_protected
            variant_binary(cbor_sign_protected->data(), item.bin_protected);

            // 2 unprotected (kid)
            if (kid.size()) {
                // 2.1 compose
                variant_set_bstr_new(value, kid.c_str(), kid.size());
                item.unprotected_map.insert(std::make_pair(cose_key_t::cose_kid, value));
                // bin_unprotected is not a member of the tobesigned
            }

            binary_t tobesigned;
            compose_tobe_processed(tobesigned, tag, convert(""), item.bin_protected, external, input);
            openssl_sign signprocessor;
            signprocessor.sign(pkey, sig, tobesigned, item.bin_data);  // signature

            handle->subitems.push_back(item);

            cbor_sign_protected->release();

            switch (method) {
                case cose_alg_t::cose_hs256_64:
                    item.bin_data.resize(64 >> 3);
                    break;
                default:
                    break;
            }
        }

        // [prototype] cbor_tag_t::cose_tag_sign only
        ret = write_signature(handle, tag, output);
    }
    __finally2 { cbor_object_signing_encryption::clear_context(handle); }

    return ret;
}

return_t cbor_object_signing::verify(cose_context_t* handle, crypto_key* key, binary_t const& input, bool& result) {
    return_t ret = errorcode_t::success;
    return_t check = errorcode_t::success;
    cbor_object_signing cose_sign;
    std::set<bool> results;
    cbor_object_signing_encryption::composer composer;

    __try2 {
        cbor_object_signing_encryption::clear_context(handle);

        ret = errorcode_t::verify;
        result = false;

        composer.parse(handle, input);

        const char* k = nullptr;

        maphint<cose_param_t, binary_t> hint(handle->binarymap);
        binary_t external;
        hint.find(cose_param_t::cose_external, &external);

        binary_t tobesigned;
        size_t size_subitems = handle->subitems.size();
        std::list<cose_parts_t>::iterator iter;
        for (iter = handle->subitems.begin(); iter != handle->subitems.end(); iter++) {
            binary_t cek;
            hint.find(cose_param_t::cose_param_cek, &cek);

            cose_parts_t& item = *iter;
            compose_tobe_processed(tobesigned, handle->cbor_tag, handle->body.bin_protected, item.bin_protected, external, handle->payload);

            int alg = 0;
            std::string kid;
            return_t check = errorcode_t::success;
            check = composer.finditem(cose_key_t::cose_alg, alg, item.protected_map);
            if (errorcode_t::success != check) {
                check = composer.finditem(cose_key_t::cose_alg, alg, handle->body.protected_map);
            }
            check = composer.finditem(cose_key_t::cose_kid, kid, item.unprotected_map);
            if (errorcode_t::success != check) {
                check = composer.finditem(cose_key_t::cose_kid, kid, handle->body.unprotected_map);
            }
            if (kid.size()) {
                k = kid.c_str();
            }

            check = doverify(handle, key, k, (cose_alg_t)alg, tobesigned, item.bin_data);
            results.insert((errorcode_t::success == check) ? true : false);
        }

        if ((1 == results.size()) && (true == *results.begin())) {
            result = true;
            ret = errorcode_t::success;
        }
    }
    __finally2 { cbor_object_signing_encryption::clear_context(handle); }
    return ret;
}

return_t cbor_object_signing::write_signature(cose_context_t* handle, uint8 tag, binary_t& signature) {
    return_t ret = errorcode_t::success;
    cbor_publisher pub;
    cbor_object_signing_encryption::composer composer;
    cbor_array* root = nullptr;
    cbor_map* cbor_body_unprotected = nullptr;

    signature.clear();

    composer.build_unprotected(&cbor_body_unprotected, handle->body.unprotected_map);

    root = new cbor_array();
    root->tag(true, (cbor_tag_t)tag);
    *root << new cbor_data(handle->body.bin_protected) << cbor_body_unprotected << new cbor_data(handle->payload) << new cbor_array();

    cbor_array* cbor_signatures = (cbor_array*)(*root)[3];
    std::list<cose_parts_t>::iterator iter;
    for (iter = handle->subitems.begin(); iter != handle->subitems.end(); iter++) {
        cose_parts_t& item = *iter;
        cbor_map* cbor_sign_unprotected = nullptr;

        composer.build_unprotected(&cbor_sign_unprotected, item.unprotected_map);

        cbor_array* cbor_signature = new cbor_array();
        *cbor_signature << new cbor_data(item.bin_protected) << cbor_sign_unprotected << new cbor_data(item.bin_data);

        *cbor_signatures << cbor_signature;
    }

    pub.publish(root, &signature);
    root->release();
    return ret;
}

return_t cbor_object_signing::doverify(cose_context_t* handle, crypto_key* key, const char* kid, cose_alg_t alg, binary_t const& tobesigned,
                                       binary_t const& signature) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    openssl_sign signprocessor;

    __try2 {
        if (nullptr == handle || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        crypt_sig_t sig = advisor->cose_sigof(alg);
        const hint_cose_algorithm_t* hint = advisor->hintof_cose_algorithm(alg);
        if (nullptr == hint) {
            ret = errorcode_t::request;  // study
            __leave2;
        }

        // RFC 8152 8.1.  ECDSA
        // In order to promote interoperability, it is suggested that SHA-256 be
        // used only with curve P-256, SHA-384 be used only with curve P-384,
        // and SHA-512 be used with curve P-521

        // json_object_signing.cpp
        // ex. key->find (kid, sig, crypto_use_t::use_sig);

        // just find out kty from algorithm
        // ecdsa-examples/ecdsa-04.json ECDSA-01: ECDSA - P-256 w/ SHA-512
        // ecdsa-examples/ecdsa-sig-04.json ECDSA-sig-01: ECDSA - P-256 w/ SHA-512 - implicit

        EVP_PKEY* pkey = nullptr;
        if (kid) {
            pkey = key->find(kid, hint->kty);
        } else {
            std::string k;
            pkey = key->select(k, hint->kty);
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
            case cose_eddsa:
                ret = signprocessor.verify(pkey, sig, tobesigned, signature);
                break;
            default:
                ret = errorcode_t::not_supported;  // studying...
                break;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing::compose_tobe_processed(binary_t& tobesigned, uint8 tag, binary_t const& body_protected, binary_t const& sign_protected,
                                                     binary_t const& external, binary_t const& payload) {
    return_t ret = errorcode_t::success;
    cbor_encode encoder;
    cbor_publisher pub;
    cbor_array* root = nullptr;

    // RFC 8152 4.4.  Signing and Verification Process
    // Sig_structure = [
    //    context : "Signature" / "Signature1" / "CounterSignature",
    //    body_protected : empty_or_serialized_map,
    //    ? sign_protected : empty_or_serialized_map,
    //    external_aad : bstr,
    //    payload : bstr
    // ]

    __try2 {
        tobesigned.clear();

        root = new cbor_array();

        if (cbor_tag_t::cose_tag_sign == tag) {
            *root << new cbor_data("Signature");
        } else if (cbor_tag_t::cose_tag_sign1 == tag) {
            *root << new cbor_data("Signature1");
        } else if (cbor_tag_t::cose_tag_mac == tag) {
            *root << new cbor_data("MAC");
        } else if (cbor_tag_t::cose_tag_mac0 == tag) {
            *root << new cbor_data("MAC0");
        } else {
            ret = errorcode_t::request;
            __leave2;
        }

        *root << new cbor_data(body_protected);
        if (cbor_tag_t::cose_tag_sign == tag) {
            // This field is omitted for the COSE_Sign1 signature structure.
            *root << new cbor_data(sign_protected);
        }
        *root << new cbor_data(external) << new cbor_data(payload);

        pub.publish(root, &tobesigned);
    }
    __finally2 {
        if (root) {
            root->release();
        }
    }

    return ret;
}

}  // namespace crypto
}  // namespace hotplace
