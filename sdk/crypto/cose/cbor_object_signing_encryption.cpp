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

cbor_object_signing_encryption::cbor_object_signing_encryption() : _builtmap(false) {
    // do nothing
}

cbor_object_signing_encryption::~cbor_object_signing_encryption() {
    // do nothing
}

return_t cbor_object_signing_encryption::open(cose_context_t** handle) {
    return_t ret = errorcode_t::success;
    cose_context_t* context = nullptr;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        __try_new_catch(context, new cose_context_t, ret, __leave2);
        context->composer = new cose_composer;
        *handle = context;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::close(cose_context_t* handle) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        delete handle->composer;
        delete handle;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::set(cose_context_t* handle, uint32 flags, uint32 debug_flags) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        handle->flags = flags;
        handle->debug_flags = debug_flags;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::get(cose_context_t* handle, uint32& flags, uint32& debug_flags) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        flags = handle->flags;
        debug_flags = handle->debug_flags;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::set(cose_context_t* handle, cose_param_t id, const binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        switch (id) {
            case cose_param_t::cose_external:
            case cose_param_t::cose_unsent_apu_id:
            case cose_param_t::cose_unsent_apu_nonce:
            case cose_param_t::cose_unsent_apu_other:
            case cose_param_t::cose_unsent_apv_id:
            case cose_param_t::cose_unsent_apv_nonce:
            case cose_param_t::cose_unsent_apv_other:
            case cose_param_t::cose_unsent_pub_other:
            case cose_param_t::cose_unsent_priv_other:
            case cose_param_t::cose_unsent_iv:
            case cose_param_t::cose_unsent_alg:
                handle->composer->get_unsent().data().replace(id, bin);
                break;
            default:
                ret = errorcode_t::bad_request;
                break;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::verify(cose_context_t* handle, crypto_key* key, const binary_t& input, bool& result) {
    return_t ret = errorcode_t::success;
    binary_t dummy;
    ret = process(handle, key, input, dummy, cose_mode_t::cose_mode_recv);
    result = (errorcode_t::success == ret);
    return ret;
}

return_t cbor_object_signing_encryption::process(cose_context_t* handle, crypto_key* key, const binary_t& cbor, binary_t& output, cose_mode_t mode) {
    return_t ret = errorcode_t::success;
    return_t check = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    std::set<return_t> results;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cose_composer* composer = handle->composer;
        if (cose_mode_t::cose_mode_recv == mode) {
            ret = composer->parse(cbor);
            if (errorcode_t::success != ret) {
                __leave2;
            }
        }

        cose_layer& body = composer->get_layer();
        cose_recipients& recipients1 = body.get_recipients();

        size_t size_recipients1 = recipients1.size();
        if (size_recipients1) {
            for (size_t index1 = 0; index1 < size_recipients1; index1++) {
                cose_layer* layer1 = recipients1[index1];
                cose_recipients& recipients2 = layer1->get_recipients();
                size_t size_recipients2 = recipients2.size();
                for (size_t index2 = 0; index2 < size_recipients2; index2++) {
                    cose_layer* layer2 = recipients2[index2];
                    check = subprocess(handle, key, layer2, mode);
                }
                check = subprocess(handle, key, layer1, mode);
                results.insert(check);
            }
            check = subprocess(handle, key, &body, mode);
            results.insert(check);
        } else {
            check = subprocess(handle, key, &body, mode);
            results.insert(check);
        }

        // RFC 8152 4.5.  Computing Counter Signatures
        cose_countersigns* countersigns1 = body.get_countersigns0();
        if (countersigns1) {
            handle->debug_flags |= cose_flag_t::cose_debug_counter_sig;
            size_t size_countersigns1 = countersigns1->size();
            for (size_t index1 = 0; index1 < size_countersigns1; index1++) {
                cose_recipient* layer1 = (*countersigns1)[index1];
                cose_countersigns* countersigns2 = layer1->get_countersigns0();
                if (countersigns2) {
                    size_t size_countersigns2 = countersigns2->size();
                    for (size_t index2 = 0; index2 < size_countersigns2; index2++) {
                        cose_recipient* layer2 = (*countersigns2)[index2];
                        check = dosign(handle, key, layer2, mode);
                        results.insert(check);
                    }
                }
                check = dosign(handle, key, layer1, mode);
                results.insert(check);
            }
        }

        if (1 == results.size()) {
            ret = *results.begin();
        } else {
            std::set<return_t>::iterator iter = results.find(errorcode_t::not_supported);
            if (results.end() == iter) {
                ret = errorcode_t::failed;
            } else {
                ret = errorcode_t::not_supported;
            }
        }

        if (cose_mode_t::cose_mode_recv == mode) {
            body.finditem(cose_param_t::cose_param_ciphertext, output, cose_scope::cose_scope_params);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::subprocess(cose_context_t* handle, crypto_key* key, cose_layer* layer, cose_mode_t mode) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        cose_composer* composer = handle->composer;

        cose_layer& body = composer->get_layer();
        cose_alg_t alg = layer->get_algorithm();
        crypt_category_t category = advisor->categoryof(alg);

        if (crypt_category_t::crypt_category_keydistribution == category) {
            ret = process_keydistribution(handle, key, layer, mode);
            if (errorcode_t::success != ret) {
                __leave2;
            }

            cose_layer* owner = layer->get_upperlayer();
            if (owner && owner->get_algorithm()) {
                // do nothing
            } else {
                if (false == _builtmap) {
                    _handlermap.insert(std::make_pair(cose_tag_encrypt, &cbor_object_signing_encryption::docrypt));
                    _handlermap.insert(std::make_pair(cose_tag_encrypt0, &cbor_object_signing_encryption::docrypt));
                    _handlermap.insert(std::make_pair(cose_tag_mac, &cbor_object_signing_encryption::domac));
                    _handlermap.insert(std::make_pair(cose_tag_mac0, &cbor_object_signing_encryption::domac));
                    _handlermap.insert(std::make_pair(cose_tag_sign, &cbor_object_signing_encryption::dosign));
                    _handlermap.insert(std::make_pair(cose_tag_sign1, &cbor_object_signing_encryption::dosign));
                    _builtmap = true;
                }

                subprocess_handler handler = nullptr;
                handler = _handlermap[composer->get_cbor_tag()];
                ret = (this->*handler)(handle, key, layer, mode);
            }
        } else if (crypt_category_t::crypt_category_crypt == category) {
            if (body.get_recipients().empty()) {
                ret = process_keydistribution(handle, key, layer, mode);
            }
            ret = docrypt(handle, key, layer, mode);
        } else if (crypt_category_t::crypt_category_mac == category) {
            if (body.get_recipients().empty()) {
                ret = process_keydistribution(handle, key, layer, mode);
            }
            ret = domac(handle, key, layer, mode);
        } else if (crypt_category_t::crypt_category_sign == category) {
            ret = dosign(handle, key, layer, mode);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::preprocess(cose_context_t* handle, crypto_key* key, std::list<cose_alg_t>& algs, crypt_category_t category,
                                                    const binary_t& input) {
    return_t ret = errorcode_t::success;
    __try2 {
        ret = preprocess_skeleton(handle, key, algs, category, input);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = preprocess_random(handle, key);
        if (errorcode_t::success != ret) {
            __leave2;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::preprocess(cose_context_t* handle, crypto_key* key, const binary_t& input) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cose_layer& body = handle->composer->get_layer();
        body.setparam(cose_param_t::cose_param_plaintext, input);

        ret = preprocess_random(handle, key);
        if (errorcode_t::success != ret) {
            __leave2;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::preprocess_skeleton(cose_context_t* handle, crypto_key* key, std::list<cose_alg_t>& algs, crypt_category_t category,
                                                             const binary_t& input) {
    return_t ret = errorcode_t::success;
    return_t check = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cose_layer& body = handle->composer->get_layer();
        body.clear();

        // check appropriate algorithms set
        uint32 flags = 0;
        std::multimap<crypt_category_t, cose_alg_t> algmap;
        for (const cose_alg_t& alg : algs) {
            const hint_cose_algorithm_t* hint = advisor->hintof_cose_algorithm(alg);
            const hint_cose_group_t* hint_group = hint->hint_group;

            flags |= hint_group->hintflags;
            algmap.insert(std::make_pair(hint_group->category, alg));
        }

        // test
        uint32 mask = 0;
        if (crypt_category_t::crypt_category_crypt == category) {
            mask = cose_hint_enc | cose_hint_agree;
        } else if (crypt_category_t::crypt_category_mac == category) {
            mask = cose_hint_mac | cose_hint_agree;
        } else if (crypt_category_t::crypt_category_sign == category) {
            mask = cose_hint_sign;
        }

        if (mask != (flags & mask)) {
            ret = errorcode_t::bad_request;
            __leave2;
        }

        // compose
        cose_alg_t main_alg = cose_alg_t::cose_unknown;
        std::multimap<crypt_category_t, cose_alg_t>::iterator algmap_iter = algmap.lower_bound(category);
        main_alg = algmap_iter->second;
        body.get_protected().add(cose_key_t::cose_alg, main_alg);
        switch (category) {
            case crypt_category_t::crypt_category_crypt:
                break;
            case crypt_category_t::crypt_category_mac:
                body.get_payload().set(input);
                break;
            case crypt_category_t::crypt_category_sign: {
                std::string kid;
                key->select(kid, main_alg);
                body.get_unprotected().add(cose_key_t::cose_kid, kid);
                body.get_payload().set(input);
            } break;
        }

        if (crypt_category_t::crypt_category_crypt == category || crypt_category_t::crypt_category_mac == category) {
            std::multimap<crypt_category_t, cose_alg_t>::iterator lower_bound, upper_bound;
            lower_bound = algmap.lower_bound(crypt_category_keydistribution);
            upper_bound = algmap.upper_bound(crypt_category_keydistribution);
            for (algmap_iter = lower_bound; algmap_iter != upper_bound; algmap_iter++) {
                cose_alg_t alg = algmap_iter->second;
                std::string kid;
                key->select(kid, alg);

                cose_recipient& recipient = body.get_recipients().add(new cose_recipient);
                recipient.get_protected().add(cose_key_t::cose_alg, alg);
                recipient.get_unprotected().add(cose_key_t::cose_kid, kid);
            }
        }

        body.setparam(cose_param_t::cose_param_plaintext, input);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::preprocess_random(cose_context_t* handle, crypto_key* key) {
    return_t ret = errorcode_t::success;
    return_t check = errorcode_t::success;
    return_t test = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cose_layer& body = handle->composer->get_layer();

        // random
        cose_recipients& recipients1 = body.get_recipients();

        std::set<return_t> results;
        size_t size_recipients1 = recipients1.size();
        if (size_recipients1) {
            for (size_t index1 = 0; index1 < size_recipients1; index1++) {
                cose_layer* layer1 = recipients1[index1];
                cose_recipients& recipients2 = layer1->get_recipients();
                size_t size_recipients2 = recipients2.size();
                for (size_t index2 = 0; index2 < size_recipients2; index2++) {
                    cose_layer* layer2 = recipients2[index2];
                    check = preprocess_dorandom(handle, key, layer2);
                    results.insert(check);
                }
                check = preprocess_dorandom(handle, key, layer1);
                results.insert(check);
            }
            check = preprocess_dorandom(handle, key, &body);
            results.insert(check);
        } else {
            check = preprocess_dorandom(handle, key, &body);
            results.insert(check);
        }

        if (1 == results.size()) {
            ret = *results.begin();
        } else {
            std::set<return_t>::iterator iter = results.find(errorcode_t::not_supported);
            if (results.end() == iter) {
                ret = errorcode_t::failed;
            } else {
                ret = errorcode_t::not_supported;
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::preprocess_dorandom(cose_context_t* handle, crypto_key* key, cose_layer* layer) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    openssl_prng prng;
    std::string kid;
    binary_t temp;

    __try2 {
        if (nullptr == handle || nullptr == key) {
            ret = errorcode_t::success;
            __leave2;
        }

        cose_alg_t alg = alg = layer->get_algorithm();
        crypt_category_t category = advisor->categoryof(alg);
        std::string kid = layer->get_kid();

        // fail if cose_key_t::cose_alg not exist
        const hint_cose_algorithm_t* hint = advisor->hintof_cose_algorithm(alg);
        if (nullptr == hint) {
            ret = errorcode_t::bad_request;
            __leave2;
        }

        // if kid not provided
        if (crypt_category_t::crypt_category_keydistribution == category && kid.empty()) {
            key->select(kid, alg);
            layer->get_unprotected().add(cose_key_t::cose_kid, kid);
        }

        const hint_cose_group_t* hint_group = hint->hint_group;
        uint32 flags = hint_group->hintflags;

        if (cose_hint_flag_t::cose_hint_iv & flags) {
            uint16 ivlen = 16;
            uint16 lsize = hint->enc.lsize;
            if (lsize) {
                ivlen = 15 - lsize;
            }

            prng.random(temp, ivlen);
            layer->get_unprotected().add(cose_key_t::cose_iv, temp);
        }
        if (cose_hint_flag_t::cose_hint_salt & flags) {
            prng.random(temp, 16);
            layer->get_unprotected().add(cose_key_t::cose_salt, temp);
        }
        if ((cose_hint_flag_t::cose_hint_epk | cose_hint_static_key) & flags) {
            crypto_key statickey;
            crypto_keychain keychain;
            binary_t bin_x;
            binary_t bin_y;
            cose_ec_curve_t curve = hint->eckey.curve;
            cose_key_t cosekey = cose_key_t::cose_key_unknown;
            if (cose_hint_flag_t::cose_hint_epk & flags) {
                cosekey = cose_ephemeral_key;  // -1
            }
            if (cose_hint_static_key & flags) {
                cosekey = cose_static_key;  // -2
            }
            uint32 nid = advisor->curveof(curve);
            keychain.add_ec(&statickey, nid, keydesc());
            statickey.get_public_key(statickey.any(), bin_x, bin_y);
            layer->get_unprotected().add(cosekey, curve, bin_x, bin_y);
        }
    }
    __finally2 {
        // do nothign
    }
    return ret;
}

return_t cbor_object_signing_encryption::compose_kdf_context(cose_context_t* handle, cose_layer* layer, binary_t& kdf_context) {
    return_t ret = errorcode_t::success;

    // RFC 8152 11.  Key Derivation Functions (KDFs)
    // RFC 8152 11.1.  HMAC-Based Extract-and-Expand Key Derivation Function (HKDF)
    // RFC 8152 11.2.  Context Information Structure

    // reversing "Context_hex" from https://github.com/cose-wg/Examples
    // ex. ./test-cbor <value of Context_hex>

    // CDDL
    //     PartyInfo = (
    //         identity : bstr / nil,
    //         nonce : bstr / int / nil,
    //         other : bstr / nil
    //     )
    //     COSE_KDF_Context = [
    //         AlgorithmID : int / tstr,
    //         PartyUInfo : [ PartyInfo ],
    //         PartyVInfo : [ PartyInfo ],
    //         SuppPubInfo : [
    //             keyDataLength : uint,
    //             protected : empty_or_serialized_map,
    //             ? other : bstr
    //         ],
    //         ? SuppPrivInfo : bstr
    //     ]

    // AlgorithmID: ... This normally is either a key wrap algorithm identifier or a content encryption algorithm identifier.

    cbor_array* root = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        int algid = 0;
        int recp_alg = 0;

        layer->finditem(cose_key_t::cose_alg, recp_alg, cose_scope::cose_scope_protected | cose_scope::cose_scope_unprotected);

        // a key wrap algorithm identifier or a content encryption algorithm identifier
        switch (recp_alg) {
            case cose_ecdhes_a128kw:
            case cose_ecdhss_a128kw:
                algid = cose_aes128kw;  // -3
                break;
            case cose_ecdhes_a192kw:
            case cose_ecdhss_a192kw:
                algid = cose_aes192kw;  // -4
                break;
            case cose_ecdhes_a256kw:
            case cose_ecdhss_a256kw:
                algid = cose_aes256kw;  // -5
                break;
            default:
                layer->get_upperlayer2()->finditem(cose_key_t::cose_alg, algid, cose_scope::cose_scope_protected | cose_scope::cose_scope_unprotected);
                break;
        }

        auto hint = advisor->hintof_cose_algorithm(algid);
        if (nullptr == hint) {
            ret = errorcode_t::not_supported;
            __leave2;
        }
        int keylen = hint->enc.ksize << 3;

        if (0 == keylen) {
            throw exception(errorcode_t::unexpected);
        }

        __try_new_catch(root, new cbor_array(), ret, __leave2);

        *root << new cbor_data(algid) << new cbor_array() << new cbor_array() << new cbor_array();
        cbor_array* partyu = (cbor_array*)(*root)[1];
        cbor_array* partyv = (cbor_array*)(*root)[2];
        cbor_array* pub = (cbor_array*)(*root)[3];
        // PartyUInfo
        {
            *partyu << compose_kdf_context_item(handle, layer, cose_key_t::cose_partyu_id, cose_param_t::cose_unsent_apu_id)
                    << compose_kdf_context_item(handle, layer, cose_key_t::cose_partyu_nonce, cose_param_t::cose_unsent_apu_nonce)
                    << compose_kdf_context_item(handle, layer, cose_key_t::cose_partyu_other, cose_param_t::cose_unsent_apu_other);
        }
        // PartyVInfo
        {
            *partyv << compose_kdf_context_item(handle, layer, cose_key_t::cose_partyv_id, cose_param_t::cose_unsent_apv_id)
                    << compose_kdf_context_item(handle, layer, cose_key_t::cose_partyv_nonce, cose_param_t::cose_unsent_apv_nonce)
                    << compose_kdf_context_item(handle, layer, cose_key_t::cose_partyv_other, cose_param_t::cose_unsent_apv_other);
        }
        // SuppPubInfo
        {
            *pub << new cbor_data(keylen) << layer->get_protected().cbor();
            binary_t bin_public;
            layer->finditem(cose_param_t::cose_unsent_pub_other, bin_public, cose_scope::cose_scope_unsent);
            if (bin_public.size()) {
                *pub << new cbor_data(bin_public);
            }
        }
        // SuppPrivInfo
        {
            binary_t bin_private;
            layer->finditem(cose_param_t::cose_unsent_priv_other, bin_private, cose_scope::cose_scope_unsent);
            if (bin_private.size()) {
                *root << new cbor_data(bin_private);
            }
        }

        cbor_publisher publisher;
        publisher.publish(root, &kdf_context);
    }
    __finally2 {
        if (root) {
            root->release();
        }
    }

    return ret;
}

cbor_data* cbor_object_signing_encryption::compose_kdf_context_item(cose_context_t* handle, cose_layer* layer, cose_key_t key, cose_param_t param) {
    return_t ret = errorcode_t::success;
    cbor_data* data = nullptr;
    binary_t bin;

    ret = layer->finditem(param, bin, cose_scope::cose_scope_unsent);
    if (errorcode_t::success != ret) {
        layer->finditem(key, bin, cose_scope::cose_scope_unprotected);
    }
    if (bin.size()) {
        data = new cbor_data(bin);
    } else {
        data = new cbor_data();  // null(F6)
    }
    return data;
}

return_t cbor_object_signing_encryption::preprocess_keydistribution(cose_context_t* handle, crypto_key* key, cose_layer* layer) {
    return_t ret = errorcode_t::success;
    return_t check = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    binary_t secret;

    __try2 {
        if (nullptr == handle || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cose_alg_t alg = cose_alg_t::cose_unknown;
        std::string kid;
        alg = layer->get_algorithm();
        kid = layer->get_kid();

        const hint_cose_algorithm_t* alg_hint = advisor->hintof_cose_algorithm(alg);
        if (nullptr == alg_hint) {
            __leave2;
        }

        layer->finditem(cose_param_t::cose_param_cek, secret, cose_scope::cose_scope_params | cose_scope::cose_scope_children);

        if (0 == secret.size()) {
            // HMAC .. read private key
            // EC/OKP .. do ECDH-ES/ECDH-SS

            cose_group_t group = alg_hint->group;
            crypto_kty_t kty = alg_hint->kty;
            crypto_keychain keychain;
            const EVP_PKEY* epk = nullptr;
            const EVP_PKEY* pkey = key->choose(kid, kty, check);
            if (nullptr == pkey) {
                handle->debug_flags |= cose_debug_notfound_key;
                __leave2;
            }

            switch (kty) {
                case crypto_kty_t::kty_oct: {
                    crypto_kty_t kty_oct;
                    key->get_privkey(pkey, kty_oct, secret, true);
                } break;
                case crypto_kty_t::kty_ec: {
                    std::string static_keyid;
                    check = layer->finditem(cose_key_t::cose_static_key_id, static_keyid, cose_scope::cose_scope_unprotected);
                    if (errorcode_t::success == check) {
                        epk = key->find(static_keyid.c_str(), kty);
                    } else {
                        epk = layer->get_static_key().any();
                    }
                    switch (group) {
                        case cose_group_t::cose_group_key_ecdhes_hmac:
                        case cose_group_t::cose_group_key_ecdhss_hmac:
                        case cose_group_t::cose_group_key_ecdhes_aeskw:
                        case cose_group_t::cose_group_key_ecdhss_aeskw:
                            dh_key_agreement(pkey, epk, secret);
                            break;
                        default:
                            break;
                    }
                } break;
                default:
                    break;
            }
        }

        layer->setparam(cose_param_t::cose_param_secret, secret);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::process_keydistribution(cose_context_t* handle, crypto_key* key, cose_layer* layer, cose_mode_t mode) {
    return_t ret = errorcode_t::success;
    return_t check = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    crypto_keychain keychain;

    __try2 {
        if (nullptr == handle || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = preprocess_keydistribution(handle, key, layer);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        cose_alg_t alg = layer->get_algorithm();
        std::string kid = layer->get_kid();
        cose_layer* source = layer->get_upperlayer2();

        const hint_cose_algorithm_t* alg_hint = advisor->hintof_cose_algorithm(alg);
        const hint_cose_algorithm_t* hint = advisor->hintof_cose_algorithm(source->get_algorithm());
        if (nullptr == alg_hint) {
            __leave2;
        }

        crypto_kty_t kty = alg_hint->kty;

        binary_t cek;
        binary_t context;
        binary_t iv;
        binary_t kek;
        binary_t kwiv;
        binary_t salt;
        binary_t secret;

        if (layer->get_upperlayer()) {
            layer->finditem(cose_param_t::cose_param_secret, secret, cose_scope::cose_scope_params | cose_scope::cose_scope_children);
            check = layer->finditem(cose_key_t::cose_iv, iv, cose_scope::cose_scope_unprotected);
            if (errorcode_t::success != check) {
                source->finditem(cose_key_t::cose_iv, iv, cose_scope::cose_scope_unprotected);
            }
            layer->finditem(cose_key_t::cose_salt, salt, cose_scope::cose_scope_unprotected);

            openssl_crypt crypt;
            openssl_hash hash;
            openssl_kdf kdf;
            openssl_prng prng;

            kwiv.resize(8);
            memset(&kwiv[0], 0xa6, kwiv.size());

            uint16 dgst_klen = 0;
            if (hint) {
                dgst_klen = hint->dgst.klen;
            }
            if (0 == dgst_klen) {
                dgst_klen = alg_hint->dgst.dlen;
            }
#if defined DEBUG
            if (istraceable()) {
                basic_stream dbs;
                dbs.println("process_keydistribution alg %i (%s)", alg, hint->name);
                trace_debug_event(trace_category_crypto, trace_event_cose_keydistribution, &dbs);
            }
#endif

            cose_group_t group = alg_hint->group;
            const char* enc_alg = alg_hint->enc.algname;
            const char* digest_alg = alg_hint->dgst.algname;
            uint16 digest_dlen = alg_hint->dgst.dlen;

            // reversing "AAD_hex", "CEK_hex", "Context_hex", "KEK_hex" from https://github.com/cose-wg/Examples

#if defined DEBUG
            if (istraceable()) {
                constexpr char constexpr_debug_alg[] = "alg %i(group %i) ";
                handle->debug_stream.printf(constexpr_debug_alg, alg, group);
            }
#endif

            if (cose_group_t::cose_group_key_direct == group) {
                // RFC 8152 12.1. Direct Encryption
                cek = secret;
            } else if (cose_group_t::cose_group_key_hkdf_hmac == group) {
                // RFC 8152 12.1.2.  Direct Key with KDF
                compose_kdf_context(handle, layer, context);

                // using context structure to transform the shared secret into the CEK
                // either the 'salt' parameter of HKDF ot the 'PartyU nonce' parameter of the context structure MUST be present.
                ret = kdf.hmac_kdf(cek, digest_alg, dgst_klen, secret, salt, context);
                // CEK solved
            } else if (cose_group_t::cose_group_key_hkdf_aes == group) {
                compose_kdf_context(handle, layer, context);

                // RFC 8152 11.1.  HMAC-Based Extract-and-Expand Key Derivation Function (HKDF)
                // RFC 8152 Table 12: HKDF Algorithms
                //      HKDF AES-MAC-128, AES-CBC-MAC-128, HKDF using AES-MAC as the PRF w/ 128-bit key
                //      HKDF AES-MAC-256, AES-CBC-MAC-256, HKDF using AES-MAC as the PRF w/ 256-bit key

                ret = kdf.hkdf_expand_aes_rfc8152(cek, digest_alg, dgst_klen, secret, context);
            } else if (cose_group_t::cose_group_key_aeskw == group) {
                kek = secret;
                binary_t payload;
                // layer->get_payload().get(payload);
                // ret = crypt.decrypt(enc_alg, kek, kwiv, payload, cek);
                if (mode) {
                    uint32 ksize = hint->enc.ksize ? hint->enc.ksize : 32;
                    binary_t temp;
                    prng.random(cek, ksize);

                    ret = crypt.encrypt(enc_alg, kek, kwiv, cek, temp);
                    layer->get_payload().set(temp);
                } else {
                    layer->get_payload().get(payload);
                    ret = crypt.decrypt(enc_alg, kek, kwiv, payload, cek);
                }
            } else if ((cose_group_t::cose_group_key_ecdhes_hmac == group) || (cose_group_t::cose_group_key_ecdhss_hmac == group)) {
                // RFC 8152 12.4.1. ECDH
                // RFC 8152 11.1.  HMAC-Based Extract-and-Expand Key Derivation Function (HKDF)
                // dh_key_agreement(pkey, epk, secret);

                compose_kdf_context(handle, layer, context);

                salt.resize(digest_dlen);
                ret = kdf.hmac_kdf(cek, digest_alg, dgst_klen, secret, salt, context);
            } else if ((cose_group_t::cose_group_key_ecdhes_aeskw == group) || (cose_group_t::cose_group_key_ecdhss_aeskw == group)) {
                // RFC 8152 12.5.1. ECDH
                // RFC 8152 12.2.1. AES Key Wrap
                // dh_key_agreement(pkey, epk, secret);

                compose_kdf_context(handle, layer, context);

                salt.resize(digest_dlen);
                kdf.hmac_kdf(kek, digest_alg, dgst_klen, secret, salt, context);

                // 12.5.  Key Agreement with Key Wrap
                binary_t payload;
                if (mode) {
                    uint32 ksize = hint->enc.ksize ? hint->enc.ksize : 32;
                    binary_t temp;
                    prng.random(cek, ksize);

                    ret = crypt.encrypt(enc_alg, kek, kwiv, cek, temp);
                    layer->get_payload().set(temp);
                } else {
                    layer->get_payload().get(payload);
                    ret = crypt.decrypt(enc_alg, kek, kwiv, payload, cek);
                }
            } else if (cose_group_t::cose_group_key_rsa_oaep == group) {
                crypt_enc_t encmode;
                switch (alg) {
                    case cose_alg_t::cose_rsaoaep1:
                        encmode = crypt_enc_t::rsa_oaep;
                        break;
                    case cose_alg_t::cose_rsaoaep256:
                        encmode = crypt_enc_t::rsa_oaep256;
                        break;
                    case cose_alg_t::cose_rsaoaep512:
                        encmode = crypt_enc_t::rsa_oaep512;
                        break;
                    default:
                        break;
                }
                const EVP_PKEY* pkey = key->choose(kid, kty, check);
                binary_t payload;
                if (mode) {
                    uint32 ksize = hint->enc.ksize ? hint->enc.ksize : 32;
                    binary_t temp;
                    prng.random(cek, ksize);
                    ret = crypt.encrypt(pkey, cek, temp, encmode);
                    layer->get_payload().set(temp);
                } else {
                    layer->get_payload().get(payload);
                    ret = crypt.decrypt(pkey, payload, cek, encmode);
                }
            }

            layer->setparam(cose_param_t::cose_param_cek, cek);

#if defined DEBUG
            if (istraceable()) {
                layer->get_composer()
                    ->get_unsent()
                    .data()
                    .add(cose_param_t::cose_param_context, context)
                    .add(cose_param_t::cose_param_iv, iv)
                    .add(cose_param_t::cose_param_kek, kek)
                    .add(cose_param_t::cose_param_salt, salt)
                    .add(cose_param_t::cose_param_secret, secret);

                auto dump = [&](const char* text, binary_t& bin) -> void {
                    if (bin.size()) {
                        basic_stream dbs;
                        dbs.println("  %-10s %s", text ? text : "", base16_encode(bin).c_str());
                        trace_debug_event(trace_category_crypto, trace_event_cose_keydistribution, &dbs);
                    }
                };

                dump("cek", cek);
                dump("context", context);
                dump("iv", iv);
                dump("kek", kek);
                dump("secret", secret);
            }
#endif
        } else {
            binary_t cek;
            const EVP_PKEY* pkey = key->choose(kid, kty, check);
            key->get_privkey(pkey, kty, cek, true);

            layer->setparam(cose_param_t::cose_param_cek, cek);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
