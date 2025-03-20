/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 8152 CBOR Object Signing and Encryption (COSE)
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/crypto_key.hpp>
#include <sdk/crypto/basic/crypto_keychain.hpp>
#include <sdk/crypto/basic/openssl_crypt.hpp>
#include <sdk/crypto/basic/openssl_ecdh.hpp>
#include <sdk/crypto/basic/openssl_hash.hpp>
#include <sdk/crypto/basic/openssl_kdf.hpp>
#include <sdk/crypto/basic/openssl_prng.hpp>
#include <sdk/crypto/basic/openssl_sign.hpp>
#include <sdk/crypto/cose/cbor_object_encryption.hpp>
#include <sdk/crypto/cose/cbor_object_signing.hpp>
#include <sdk/crypto/cose/cbor_object_signing_encryption.hpp>
#include <sdk/crypto/cose/cose_composer.hpp>
#include <set>

namespace hotplace {
namespace crypto {

return_t cbor_object_signing_encryption::sign(cose_context_t* handle, crypto_key* key, cose_alg_t alg, const binary_t& input, binary_t& output) {
    return_t ret = errorcode_t::success;
    std::list<cose_alg_t> algs;
    algs.push_back(alg);
    ret = sign(handle, key, algs, input, output);
    return ret;
}

return_t cbor_object_signing_encryption::sign(cose_context_t* handle, crypto_key* key, std::list<cose_alg_t>& algs, const binary_t& input, binary_t& output) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = preprocess(handle, key, algs, crypt_category_t::crypt_category_sign, input);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        handle->composer->_cbor_tag = cbor_tag_unknown;
        ret = process(handle, key, input, output, cose_mode_t::cose_mode_send);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        cbor_array* root = nullptr;
        handle->composer->compose(&root, output);
        root->release();
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::sign(cose_context_t* handle, crypto_key* key, const binary_t& input, binary_t& output) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = preprocess(handle, key, input);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = preprocess_random(handle, key);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        handle->composer->_cbor_tag = cbor_tag_unknown;
        ret = process(handle, key, input, output, cose_mode_t::cose_mode_send);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        cbor_array* root = nullptr;
        handle->composer->compose(&root, output);
        root->release();
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::compose_sign_context(cose_context_t* handle, cose_layer* layer, binary_t& tobesigned) {
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

        cose_layer& body = handle->composer->get_layer();

        size_t size_recipients = body.get_recipients().size();
        binary_t external;
        binary_t payload;
        layer->finditem(cose_param_t::cose_external, external, cose_scope::cose_scope_unsent);
        body.get_payload().get(payload);

        /**
         * cose_tag_sign        protected, unprotected_map, payload,    [+signature]
         * cose_tag_sign1       protected, unprotected_map, payload,    signature
         */

        root = new cbor_array();

        if (layer->get_property() & cose_property_t::cose_property_countersign) {
            *root << new cbor_data("CounterSignature");
        } else if (size_recipients) {
            *root << new cbor_data("Signature");
        } else {
            *root << new cbor_data("Signature1");
        }

        *root << body.get_protected().cbor();
        if (layer->get_upperlayer()) {
            *root << layer->get_protected().cbor();
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

return_t cbor_object_signing_encryption::dosign(cose_context_t* handle, crypto_key* key, cose_layer* layer, cose_mode_t mode) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    openssl_sign signprocessor;
    __try2 {
        binary_t tobesigned;
        compose_sign_context(handle, layer, tobesigned);
        cose_alg_t alg = layer->get_algorithm();
        std::string kid = layer->get_kid();
        binary_t signature;

        crypt_sig_t sig = advisor->sigof(alg);
        const hint_cose_algorithm_t* hint = advisor->hintof_cose_algorithm(alg);
        if (nullptr == hint) {
            ret = errorcode_t::bad_request;
            __leave2;
        }

        if (istraceable()) {
            basic_stream dbs;
            dbs.printf("dosign alg %i (%s)\n", alg, hint->name);
            trace_debug_event(category_crypto, crypto_event_cose, &dbs);
        }

        // RFC 8152 8.1.  ECDSA
        // In order to promote interoperability, it is suggested that SHA-256 be
        // used only with curve P-256, SHA-384 be used only with curve P-384,
        // and SHA-512 be used with curve P-521

        // json_object_signing.cpp
        // ex. key->find (kid, sig, crypto_use_t::use_sig);

        // just find out kty
        // ecdsa-examples/ecdsa-04.json ECDSA-01: ECDSA - P-256 w/ SHA-512
        // ecdsa-examples/ecdsa-sig-04.json ECDSA-sig-01: ECDSA - P-256 w/ SHA-512 - implicit

        const EVP_PKEY* pkey = nullptr;
        if (kid.size()) {
            pkey = key->find(kid.c_str(), hint->kty);
        } else {
            std::string k;
            pkey = key->select(k, hint->kty);
        }

        cose_group_t group = hint->group;
        switch (group) {
            case cose_group_sign_ecdsa:
            case cose_group_sign_eddsa:
            case cose_group_sign_rsassa_pss:
            case cose_group_sign_rsassa_pkcs15:
                if (mode) {
                    binary_t sign;
                    ret = signprocessor.sign(pkey, sig, tobesigned, signature);
                    layer->get_signature().set(signature);
                } else {
                    if (layer->get_property() & cose_property_t::cose_property_countersign) {
                        layer->get_signature().get(signature);
                    } else if (layer->get_upperlayer()) {
                        layer->get_payload().get(signature);
                    } else {
                        layer->get_signature().get(signature);
                    }

                    ret = signprocessor.verify(pkey, sig, tobesigned, signature);
                }
                break;
            default:
                ret = errorcode_t::bad_request;
                break;
        }

        if (istraceable()) {
            auto dump = [&](const char* text, binary_t& bin) -> void {
                if (bin.size()) {
                    basic_stream dbs;
                    dbs.printf("  %-10s %s\n", text ? text : "", base16_encode(bin).c_str());
                    trace_debug_event(category_crypto, crypto_event_cose, &dbs);
                }
            };

            dump("tobesigned", tobesigned);
            dump("signature", signature);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
