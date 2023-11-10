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

#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/openssl_crypt.hpp>
#include <sdk/crypto/basic/openssl_hash.hpp>
#include <sdk/crypto/basic/openssl_sign.hpp>
#include <sdk/crypto/cose/cbor_object_signing.hpp>
#include <sdk/crypto/cose/cose_composer.hpp>
#include <sdk/io/cbor/cbor_array.hpp>
#include <sdk/io/cbor/cbor_data.hpp>
#include <sdk/io/cbor/cbor_encode.hpp>
#include <sdk/io/cbor/cbor_map.hpp>
#include <sdk/io/cbor/cbor_publisher.hpp>
#include <sdk/io/cbor/cbor_reader.hpp>
#include <sdk/io/cbor/concise_binary_object_representation.hpp>

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
    cbor_object_signing_encryption cose;
    cbor_object_signing_encryption::parser parser;

    __try2 {
        cose.clear_context(handle);

        if (nullptr == handle || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cose_structure_t& body = handle->body;

        handle->cbor_tag = cbor_tag_t::cose_tag_sign;
        body.bin_payload = input;

        cbor_tag_t tag = cbor_tag_t::cose_tag_sign;
        cbor_object_signing_encryption_composer::composer composer;
        cbor_publisher pub;
        std::list<cose_alg_t>::iterator iter;

        for (iter = methods.begin(); iter != methods.end(); iter++) {
            cose_alg_t method = *iter;
            crypt_sig_t sig = advisor->sigof(method);

            std::string kid;
            const EVP_PKEY* pkey = key->select(kid, sig);
            // subitem of handle
            cose_structure_t* item = nullptr;
            __try_new_catch_only(item, new cose_structure_t);
            if (nullptr == item) {
                ret = errorcode_t::out_of_memory;
                break;
            }

            // composer
            // create a binary using cbor_pushlisher and put it into subitem of handle
            cbor_data* cbor_sign_protected = nullptr;

            binary_t temp;

            // 1 protected (alg)
            // 1.1 compose
            variant_t value;
            variant_set_int16(value, method);
            item->protected_map.insert(std::make_pair(cose_key_t::cose_alg, value));
            composer.build_protected(&cbor_sign_protected, item->protected_map);
            // 1.2 bin_protected
            variant_binary(cbor_sign_protected->data(), item->bin_protected);

            // 2 unprotected (kid)
            if (kid.size()) {
                // 2.1 compose
                variant_set_bstr_new(value, (unsigned char*)kid.c_str(), kid.size());
                item->unprotected_map.insert(std::make_pair(cose_key_t::cose_kid, value));
                // bin_unprotected is not a member of the tobesigned
            }

            binary_t tobesigned;
            parser.compose_sig_structure(handle, *item, tobesigned);
            openssl_sign signprocessor;
            signprocessor.sign(pkey, sig, tobesigned, item->bin_payload);  // signature

            body.add(item);

            cbor_sign_protected->release();

            switch (method) {
                case cose_alg_t::cose_hs256_64:
                    item->bin_payload.resize(64 >> 3);
                    break;
                default:
                    break;
            }
        }

        if (errorcode_t::success != ret) {
            __leave2;
        }

        // [prototype] cbor_tag_t::cose_tag_sign only
        ret = write_signature(handle, tag, output);
    }
    __finally2 {
        cose.clear_context(handle);
        // do nothing
    }

    return ret;
}

return_t cbor_object_signing::mac(cose_context_t* handle, crypto_key* key, cose_alg_t method, binary_t const& input, binary_t& output) {
    return_t ret = errorcode_t::success;

    return ret;
}

return_t cbor_object_signing::mac(cose_context_t* handle, crypto_key* key, std::list<cose_alg_t> methods, binary_t const& input, binary_t& output) {
    return_t ret = errorcode_t::success;

    return ret;
}

return_t cbor_object_signing::verify(cose_context_t* handle, crypto_key* key, binary_t const& input, bool& result) {
    return_t ret = errorcode_t::success;
    cbor_object_signing_encryption cose;
    cbor_object_signing_encryption::parser parser;
    // cbor_object_signing_encryption_composer::composer composer;
    __try2 {
        cose.clear_context(handle);
        result = false;

        if (nullptr == handle || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = parser.parse(handle, input);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        switch (handle->cbor_tag) {
            case cbor_tag_t::cose_tag_sign:
            case cbor_tag_t::cose_tag_sign1:
                ret = doverify_sign(handle, key);
                break;
            case cbor_tag_t::cose_tag_mac:
            case cbor_tag_t::cose_tag_mac0:
                ret = doverify_mac(handle, key);
                break;
        }
        if (errorcode_t::success == ret) {
            result = true;
        }
    }
    __finally2 {
        cose.clear_context(handle);
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing::write_signature(cose_context_t* handle, uint8 tag, binary_t& signature) {
    return_t ret = errorcode_t::success;
    cbor_publisher pub;
    cbor_object_signing_encryption_composer::composer composer;
    cbor_array* root = nullptr;
    cbor_map* cbor_body_unprotected = nullptr;

    cose_structure_t& body = handle->body;

    signature.clear();

    composer.build_unprotected(&cbor_body_unprotected, body.unprotected_map);

    root = new cbor_array();
    root->tag((cbor_tag_t)tag);
    *root << new cbor_data(body.bin_protected) << cbor_body_unprotected << new cbor_data(body.bin_payload) << new cbor_array();

    cbor_array* cbor_signatures = (cbor_array*)(*root)[3];
    std::list<cose_structure_t*>::iterator iter;
    for (iter = body.multiitems.begin(); iter != body.multiitems.end(); iter++) {
        cose_structure_t* item = *iter;
        cbor_map* cbor_sign_unprotected = nullptr;

        composer.build_unprotected(&cbor_sign_unprotected, item->unprotected_map);

        cbor_array* cbor_signature = new cbor_array();
        *cbor_signature << new cbor_data(item->bin_protected) << cbor_sign_unprotected << new cbor_data(item->bin_payload);

        *cbor_signatures << cbor_signature;
    }

    pub.publish(root, &signature);
    root->release();
    return ret;
}

return_t cbor_object_signing::doverify_sign(cose_context_t* handle, crypto_key* key) {
    return_t ret = errorcode_t::success;
    return_t check = errorcode_t::success;
    std::set<bool> results;

    __try2 {
        if (nullptr == handle || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cose_structure_t& body = handle->body;

        size_t size_multiitems = body.multiitems.size();
        if (0 == size_multiitems) {
            check = doverify_sign(handle, key, body, body.singleitem);
            results.insert((errorcode_t::success == check) ? true : false);
        } else {
            std::list<cose_structure_t*>::iterator iter;
            for (iter = body.multiitems.begin(); iter != body.multiitems.end(); iter++) {
                cose_structure_t* item = *iter;

                check = doverify_sign(handle, key, *item, item->bin_payload);
                results.insert((errorcode_t::success == check) ? true : false);
            }
        }

        if ((1 == results.size()) && (true == *results.begin())) {
            ret = errorcode_t::success;
        } else {
            ret = errorcode_t::error_verify;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing::doverify_sign(cose_context_t* handle, crypto_key* key, cose_structure_t& item, binary_t const& signature) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    cbor_object_signing_encryption::parser parser;
    // cbor_object_signing_encryption_composer::composer composer;
    openssl_sign signprocessor;

    __try2 {
        if (nullptr == handle || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cose_structure_t& body = handle->body;

        cose_alg_t alg = cose_alg_t::cose_unknown;
        std::string kid;
        if (item.parent) {
            alg = item.alg;
            kid = item.kid;
        }
        if (0 == alg) {
            alg = body.alg;
        }
        if (kid.empty()) {
            kid = body.kid;
        }

        binary_t tobesigned;
        parser.compose_sig_structure(handle, item, tobesigned);

        crypt_sig_t sig = advisor->sigof(alg);
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
                ret = signprocessor.verify(pkey, sig, tobesigned, signature);
                break;
            default:
                ret = errorcode_t::request;
                break;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing::doverify_mac(cose_context_t* handle, crypto_key* key) {
    return_t ret = errorcode_t::success;
    return_t check = errorcode_t::success;
    std::set<bool> results;
    cbor_object_signing_encryption cose;

    // RFC 8152 4.3.  Externally Supplied Data
    // RFC 8152 5.3.  How to Encrypt and Decrypt for AEAD Algorithms
    // RFC 8152 5.4.  How to Encrypt and Decrypt for AE Algorithms
    // RFC 8152 11.2.  Context Information Structure

    __try2 {
        if (nullptr == handle || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cose_structure_t& body = handle->body;

        bool do_encrypt = false;
        size_t size_multiitems = body.multiitems.size();
        if (0 == size_multiitems) {
            cose.process_keyagreement(handle, key, body, do_encrypt);
            check = doverify_mac(handle, key, body, body.singleitem);
            results.insert((errorcode_t::success == check) ? true : false);
        } else {
            std::list<cose_structure_t*>::iterator iter;
            for (iter = body.multiitems.begin(); iter != body.multiitems.end(); iter++) {
                cose_structure_t* item = *iter;

                cose.process_keyagreement(handle, key, *item, do_encrypt);
                check = doverify_mac(handle, key, *item, item->bin_payload);
                results.insert((errorcode_t::success == check) ? true : false);
            }
        }

        if ((1 == results.size()) && (true == *results.begin())) {
            ret = errorcode_t::success;
        } else {
            ret = errorcode_t::error_verify;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing::doverify_mac(cose_context_t* handle, crypto_key* key, cose_structure_t& item, binary_t const& tag) {
    return_t ret = errorcode_t::success;
    return_t check = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    cbor_object_signing_encryption::parser parser;
    // cbor_object_signing_encryption_composer::composer composer;
    int enc_alg = 0;

    __try2 {
        if (nullptr == handle || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cose_structure_t& body = handle->body;

        cose_alg_t alg = cose_alg_t::cose_unknown;
        std::string kid;
        binary_t cek;
        binary_t iv;
        binary_t partial_iv;
        binary_t tag;
        binary_t tomac;

        alg = body.alg;
        if (item.parent) {
            kid = item.kid;
            parser.finditem(cose_key_t::cose_iv, iv, item.unprotected_map);
            parser.finditem(cose_key_t::cose_partial_iv, partial_iv, item.unprotected_map);
            cek = item.binarymap[cose_param_t::cose_param_cek];
        } else {
            cek = handle->binarymap[cose_param_t::cose_param_cek];
        }
        if (kid.empty()) {
            kid = body.kid;
        }
        if (0 == iv.size()) {
            parser.finditem(cose_key_t::cose_iv, iv, body.unprotected_map);
            if (0 == iv.size()) {
                iv = handle->binarymap[cose_param_t::cose_unsent_iv];
            }
        }
        if (0 == partial_iv.size()) {
            parser.finditem(cose_key_t::cose_partial_iv, partial_iv, body.unprotected_map);
        }

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

            if (cose_flag_t::cose_flag_allow_debug & handle->flags) {
                handle->debug_flags = cose_flag_t::cose_debug_partial_iv;
            }
        }

        parser.compose_mac_structure(handle, tomac);

        const hint_cose_algorithm_t* hint = advisor->hintof_cose_algorithm(alg);
        if (nullptr == hint) {
            ret = errorcode_t::request;  // study
            __leave2;
        }

        uint8 cbor_tag = handle->cbor_tag;
        if (0 == cek.size()) {
            ret = errorcode_t::no_data;
            __leave2;
        }

        const EVP_PKEY* pkey = nullptr;
        if (kid.size()) {
            pkey = key->find(kid.c_str(), hint->kty);
        } else {
            std::string k;
            pkey = key->select(k, hint->kty);
        }

        openssl_mac mac;
        cose_group_t group = hint->group;
        if (cose_group_t::cose_group_hash == group) {
            throw;
        } else if (cose_group_t::cose_group_mac_hmac == group) {
            ret = mac.hmac(hint->dgst.algname, cek, tomac, tag);
            tag.resize(hint->dgst.dlen);  // sha256/64, sha512/256
        } else if (cose_group_t::cose_group_mac_aes == group) {
            binary_t q;
            binary_t iv;
            iv.resize(16);  // If the IV can be modified, then messages can be forged.  This is addressed by fixing the IV to all zeros.
            openssl_mac mac;
            ret = mac.cbc_mac_rfc8152(hint->enc.algname, cek, iv, tomac, tag, hint->enc.tsize);
        } else {
            ret = errorcode_t::request;
            __leave2;
        }

        if (tag != body.singleitem) {
            ret = errorcode_t::error_verify;
        }

        if (errorcode_t::success != ret) {
            __leave2;
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

}  // namespace crypto
}  // namespace hotplace
