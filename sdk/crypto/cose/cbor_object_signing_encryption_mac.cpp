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

#include <sdk/base/nostd/exception.hpp>
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

return_t cbor_object_signing_encryption::mac(cose_context_t* handle, crypto_key* key, std::list<cose_alg_t>& algs, const binary_t& input, binary_t& output) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == handle || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = preprocess(handle, key, algs, crypt_category_t::crypt_category_mac, input);
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

return_t cbor_object_signing_encryption::mac(cose_context_t* handle, crypto_key* key, const binary_t& input, binary_t& output) {
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

return_t cbor_object_signing_encryption::compose_mac_context(cose_context_t* handle, cose_layer* layer, binary_t& tomac) {
    return_t ret = errorcode_t::success;
    cbor_encode encoder;
    cbor_publisher pub;
    cbor_array* root = nullptr;

    // RFC 8152 6.3.  How to Compute and Verify a MAC
    // MAC_structure = [
    //     context : "MAC" / "MAC0",
    //     protected : empty_or_serialized_map,
    //     external_aad : bstr,
    //     payload : bstr
    // ]

    __try2 {
        tomac.clear();

        cose_layer& body = handle->composer->get_layer();

        size_t size_recipients = body.get_recipients().size();
        binary_t external;
        binary_t payload;
        layer->finditem(cose_param_t::cose_external, external, cose_scope::cose_scope_unsent);
        body.get_payload().get(payload);

        /**
         * cose_tag_mac         protected, unprotected_map, payload,    tag,            [+recipient]
         * cose_tag_mac0        protected, unprotected_map, payload,    tag
         */

        root = new cbor_array();

        if (size_recipients) {
            *root << new cbor_data("MAC");
        } else {
            *root << new cbor_data("MAC0");
        }

        *root << layer->get_protected().cbor() << new cbor_data(external) << new cbor_data(payload);

        pub.publish(root, &tomac);
    }
    __finally2 {
        if (root) {
            root->release();
        }
    }

    return ret;
}

return_t cbor_object_signing_encryption::domac(cose_context_t* handle, crypto_key* key, cose_layer* layer, cose_mode_t mode) {
    return_t ret = errorcode_t::success;
    return_t check = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    int enc_alg = 0;

    __try2 {
        if (nullptr == handle || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cose_layer& body = handle->composer->get_layer();
        cose_layer* source = layer->get_upperlayer2();
        cose_alg_t alg = layer->get_algorithm();
        std::string kid = layer->get_kid();
        binary_t cek;
        binary_t iv;
        binary_t partial_iv;
        binary_t tag;
        binary_t tomac;

        const hint_cose_algorithm_t* hint = advisor->hintof_cose_algorithm(alg);
        if (nullptr == hint) {
            ret = errorcode_t::bad_request;  // study
            __leave2;
        }

        check = layer->finditem(cose_key_t::cose_iv, iv, cose_scope::cose_scope_unprotected);
        if (errorcode_t::success != check) {
            source->finditem(cose_param_t::cose_unsent_iv, iv, cose_scope::cose_scope_unsent);
        }
        layer->finditem(cose_key_t::cose_partial_iv, partial_iv, cose_scope::cose_scope_unprotected);
        layer->finditem(cose_param_t::cose_param_cek, cek, cose_scope::cose_scope_params | cose_scope::cose_scope_children);

        if (0 == cek.size()) {
            ret = errorcode_t::no_data;
            __leave2;
        }

#if defined DEBUG
        if (istraceable()) {
            basic_stream dbs;
            dbs.println("domac alg %i (%s)", alg, hint->name);
            trace_debug_event(trace_category_crypto, trace_event_cose_mac, &dbs);
        }
#endif

        if (iv.size() && partial_iv.size()) {
            // TEST FAILED
            // test vector wrong ?

            // RFC 8152 3.1.  Common COSE Headers Parameters
            // Partial IV
            // 1.  Left-pad the Partial IV with zeros to the length of IV.
            // 2.  XOR the padded Partial IV with the context IV.

            // size_t ivsize = iv.size();
            // binary_t aligned_partial_iv;
            // binary_load(aligned_partial_iv, ivsize, &partial_iv[0], partial_iv.size());
            // for (size_t i = 0; i < ivsize; i++) {
            //     iv[i] ^= aligned_partial_iv[i];
            // }

            handle->debug_flags |= cose_flag_t::cose_debug_partial_iv;
        }

        compose_mac_context(handle, layer, tomac);

        const EVP_PKEY* pkey = nullptr;
        if (kid.size()) {
            pkey = key->find(kid.c_str(), hint->kty);
        }

        openssl_mac mac;
        cose_group_t group = hint->group;
        if (cose_group_t::cose_group_hash == group) {
            throw exception(not_implemented);
        } else if (cose_group_t::cose_group_mac_hmac == group) {
            ret = mac.hmac(hint->dgst.algname, cek, tomac, tag);
            tag.resize(hint->dgst.dlen);  // sha256/64, sha512/256
        } else if (cose_group_t::cose_group_mac_aes == group) {
            binary_t q;
            binary_t iv;
            iv.resize(16);  // If the IV can be modified, then messages can be forged.  This is addressed by fixing the IV to all zeros.
            openssl_mac mac;
            ret = mac.cbc_mac(hint->enc.algname, cek, iv, tomac, tag, hint->enc.tsize);
        } else {
            ret = errorcode_t::bad_request;
            __leave2;
        }

        if (mode) {
            body.get_tag().set(tag);
        } else {
            binary_t tagvalue;
            body.get_tag().get(tagvalue);

            if (tag != tagvalue) {
                ret = errorcode_t::error_verify;
                __leave2;
            }
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

}  // namespace crypto
}  // namespace hotplace
