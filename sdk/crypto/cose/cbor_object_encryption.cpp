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
#include <sdk/crypto/basic/openssl_ecdh.hpp>
#include <sdk/crypto/basic/openssl_hash.hpp>
#include <sdk/crypto/basic/openssl_kdf.hpp>
#include <sdk/crypto/basic/openssl_prng.hpp>
#include <sdk/crypto/basic/openssl_sign.hpp>
#include <sdk/crypto/cose/cbor_object_encryption.hpp>
#include <sdk/crypto/cose/cose_composer.hpp>
#include <sdk/io/cbor/cbor_array.hpp>
#include <sdk/io/cbor/cbor_data.hpp>
#include <sdk/io/cbor/cbor_encode.hpp>
#include <sdk/io/cbor/cbor_map.hpp>
#include <sdk/io/cbor/cbor_publisher.hpp>
#include <sdk/io/cbor/cbor_reader.hpp>
#include <sdk/io/types.hpp>

namespace hotplace {
namespace crypto {

cbor_object_encryption::cbor_object_encryption() {
    // do nothing
}

cbor_object_encryption::~cbor_object_encryption() {
    // do nothing
}

#if 0
return_t cbor_object_encryption::encrypt(cose_context_t* handle, crypto_key* key, cose_alg_t method, binary_t const& input, binary_t& output) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        std::list<cose_alg_t> methods;
        methods.push_back(method);

        ret = encrypt(handle, key, methods, input, output);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_encryption::encrypt(cose_context_t* handle, crypto_key* key, std::list<cose_alg_t> methods, binary_t const& input, binary_t& output) {
    return_t ret = errorcode_t::success;
    return_t check = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    std::set<return_t> results;
    cbor_object_signing_encryption cose;
    cbor_publisher publisher;

    __try2 {
        cose.clear_context(handle);

        if (nullptr == handle || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = prepare_encrypt(handle, key, methods);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        cose_structure_t& structure = handle->body;
        binary_t ciphertext;
        bool do_encrypt = true;
        size_t size_multiitems = structure.multiitems.size();
        if (0 == size_multiitems) {
            handle->cbor_tag = cbor_tag_t::cose_tag_encrypt;
            cose.process_keyagreement(handle, key, structure, do_encrypt);
            check = doencrypt(handle, key, structure, input, ciphertext);
            results.insert(check);
        } else {
            handle->cbor_tag = cbor_tag_t::cose_tag_encrypt0;
            std::list<cose_structure_t*>::iterator iter;
            for (iter = structure.multiitems.begin(); iter != structure.multiitems.end(); iter++) {
                cose_structure_t* item = *iter;

                std::list<cose_structure_t*>::iterator layered_iter;
                for (layered_iter = item->multiitems.begin(); layered_iter != item->multiitems.end(); layered_iter++) {
                    cose_structure_t* layered_item = *layered_iter;
                    cose.process_keyagreement(handle, key, *layered_item, do_encrypt);  // KEK
                }

                cose.process_keyagreement(handle, key, *item, do_encrypt);  // CEK
                check = doencrypt(handle, key, *item, input, ciphertext);
                results.insert(check);
            }
        }

        if (1 == results.size()) {
            ret = *results.begin();
        } else {
            ret = errorcode_t::error_verify;
        }
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // compose
        cbor_array* root = new cbor_array();
        root->tag(cbor_tag_t::cose_tag_encrypt);

        compose(root, handle->body, ciphertext);
        if (size_multiitems) {
            cbor_array* recipients = new cbor_array();

            std::list<cose_structure_t*>::iterator iter;
            for (iter = structure.multiitems.begin(); iter != structure.multiitems.end(); iter++) {
                cose_structure_t* item = *iter;
                compose(recipients, *item);
            }
            *root << recipients;
        }
        publisher.publish(root, &output);
        root->release();
    }
    __finally2 { cose.clear_context(handle); }
    return ret;
}

return_t cbor_object_encryption::encrypt(cose_context_t* handle, crypto_key* key, cose_alg_t* methods, size_t size_method, binary_t const& input,
                                         binary_t& output) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle || nullptr == key || nullptr == methods) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        std::list<cose_alg_t> algs;
        for (size_t i = 0; i < size_method; i++) {
            algs.push_back(methods[i]);
        }
        ret = encrypt(handle, key, algs, input, output);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_encryption::compose(cbor_array* base, cose_structure_t& item, binary_t const& ciphertext) {
    return_t ret = errorcode_t::success;
    cose_composer::composer composer;

    cbor_data* cbor_protected_map = nullptr;
    cbor_map* cbor_unprotected_map = nullptr;
    cbor_data* cbor_ciphertext = nullptr;
    composer.build_protected(&cbor_protected_map, item.protected_map);
    composer.build_unprotected(&cbor_unprotected_map, item.unprotected_map);
    composer.build_data(&cbor_ciphertext, ciphertext);

    *base << cbor_protected_map << cbor_unprotected_map << cbor_ciphertext;

    return ret;
}

return_t cbor_object_encryption::compose(cbor_array* base, cose_structure_t& item) {
    return_t ret = errorcode_t::success;
    cose_composer::composer composer;
    cbor_publisher publisher;

    cbor_data* cbor_protected_map = nullptr;
    cbor_map* cbor_unprotected_map = nullptr;
    cbor_data* cbor_payload = new cbor_data(item.bin_payload);
    composer.build_protected(&cbor_protected_map, item.protected_map);
    composer.build_unprotected(&cbor_unprotected_map, item.unprotected_map);

    *base << cbor_protected_map << cbor_unprotected_map << cbor_payload;

    return ret;
}

return_t cbor_object_encryption::prepare_encrypt(cose_context_t* handle, crypto_key* key, std::list<cose_alg_t> methods) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    cbor_object_signing_encryption cose;
    cose_composer::composer composer;
    cbor_publisher publisher;

    __try2 {
        cose_alg_t enc_alg = cose_unknown;
        uint32 skipflags = cose_hint_flag_t::cose_hint_not_supported | cose_hint_flag_t::cose_hint_sign | cose_hint_flag_t::cose_hint_mac;
        uint32 flags = 0;

        // random
        std::list<cose_alg_t>::iterator iter;
        for (iter = methods.begin(); iter != methods.end(); iter++) {
            cose_alg_t alg = *iter;

            const hint_cose_algorithm_t* hint = advisor->hintof_cose_algorithm(alg);
            if (nullptr == hint) {
                continue;
            }

            const hint_cose_group_t* hint_group = hint->hint_group;
            if (hint_group->hintflags & skipflags) {
                continue;
            }

            flags |= hint_group->hintflags;

            if (hint_group->hintflags & cose_hint_flag_t::cose_hint_enc) {
                cose_structure_t& body = handle->body;
                body.alg = alg;
                dorandom(handle, key, alg, body);
            } else {
                cose_structure_t* item = nullptr;
                __try_new_catch_only(item, new cose_structure_t);
                if (item) {
                    item->alg = alg;
                    dorandom(handle, key, alg, *item);
                    handle->body.add(item);
                } else {
                    ret = errorcode_t::out_of_memory;
                    break;
                }
            }
        }

        if (errorcode_t::success != ret) {
            __leave2;
        }

        if (0 == (cose_hint_flag_t::cose_hint_enc & flags)) {
            ret = errorcode_t::request;
            __leave2;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_encryption::dorandom(cose_context_t* handle, crypto_key* key, cose_alg_t alg, cose_structure_t& item) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        if (nullptr == handle || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 handle_flags = handle->flags;

        const hint_cose_algorithm_t* hint = advisor->hintof_cose_algorithm(alg);
        const hint_cose_group_t* hint_group = hint->hint_group;

        uint32 flags = hint_group->hintflags;

        openssl_prng prng;
        std::string kid;
        binary_t temp;
        variant_t value;

        variant_set_int16(value, alg);
        item.protected_map.insert(std::make_pair(cose_key_t::cose_alg, value));

        if (cose_hint_flag_t::cose_hint_iv & flags) {
            if (handle->binarymap[cose_param_t::cose_unsent_iv].empty()) {
                uint16 ivlen = 16;
                uint16 lsize = hint->enc.lsize;
                if (lsize) {
                    ivlen = 15 - lsize;
                }
                prng.random(temp, ivlen);
                handle->binarymap[cose_param_t::cose_param_iv] = temp;

                variant_t value;
                variant_set_binary_new(value, temp);
                item.unprotected_map.insert(std::make_pair(cose_key_t::cose_iv, value));

                if (cose_flag_t::cose_flag_allow_debug & handle->flags) {
                    handle->debug_stream.printf("iv ");
                }
            }
        }

        if (cose_hint_flag_t::cose_hint_salt & flags) {
            prng.random(temp, 32);
            item.binarymap[cose_param_t::cose_param_salt] = temp;

            variant_set_binary_new(value, temp);
            item.unprotected_map.insert(std::make_pair(cose_key_t::cose_salt, value));

            if (cose_flag_t::cose_flag_allow_debug & handle->flags) {
                handle->debug_stream.printf("salt ");
            }
        }

        if (cose_hint_flag_t::cose_hint_party & flags) {
            if (handle->binarymap[cose_param_t::cose_unsent_apu_id].empty()) {
                prng.random(temp, 4);
                item.binarymap[cose_param_t::cose_param_apu_id] = temp;

                variant_set_binary_new(value, temp);
                item.unprotected_map.insert(std::make_pair(cose_key_t::cose_partyu_id, value));
            }
            if (handle->binarymap[cose_param_t::cose_unsent_apu_nonce].empty()) {
                prng.random(temp, 4);
                item.binarymap[cose_param_t::cose_param_apu_nonce] = temp;

                variant_set_binary_new(value, temp);
                item.unprotected_map.insert(std::make_pair(cose_key_t::cose_partyu_nonce, value));
            }
            if (handle->binarymap[cose_param_t::cose_unsent_apu_other].empty()) {
                prng.random(temp, 4);
                item.binarymap[cose_param_t::cose_param_apu_other] = temp;

                variant_set_binary_new(value, temp);
                item.unprotected_map.insert(std::make_pair(cose_key_t::cose_partyu_other, value));
            }
            if (handle->binarymap[cose_param_t::cose_unsent_apv_id].empty()) {
                prng.random(temp, 4);
                item.binarymap[cose_param_t::cose_param_apv_id] = temp;

                variant_set_binary_new(value, temp);
                item.unprotected_map.insert(std::make_pair(cose_key_t::cose_partyv_id, value));
            }
            if (handle->binarymap[cose_param_t::cose_unsent_apv_nonce].empty()) {
                prng.random(temp, 4);
                item.binarymap[cose_param_t::cose_param_apv_nonce] = temp;

                variant_set_binary_new(value, temp);
                item.unprotected_map.insert(std::make_pair(cose_key_t::cose_partyv_nonce, value));
            }
            if (handle->binarymap[cose_param_t::cose_unsent_apv_other].empty()) {
                prng.random(temp, 4);
                item.binarymap[cose_param_t::cose_param_apv_other] = temp;

                variant_set_binary_new(value, temp);
                item.unprotected_map.insert(std::make_pair(cose_key_t::cose_partyv_other, value));
            }
            if (handle->binarymap[cose_param_t::cose_unsent_pub_other].empty()) {
                prng.random(temp, 4);
                item.binarymap[cose_param_t::cose_param_pub_other] = temp;
            }
            if (handle->binarymap[cose_param_t::cose_unsent_priv_other].empty()) {
                prng.random(temp, 4);
                item.binarymap[cose_param_t::cose_param_priv_other] = temp;
            }

            if (cose_flag_t::cose_flag_allow_debug & handle->flags) {
                handle->debug_stream.printf("party ");
            }
        }

        if (cose_hint_flag_t::cose_hint_kek & flags) {
            uint32 ksize = hint->enc.ksize ? hint->enc.ksize : 32;
            prng.random(temp, ksize);
            item.bin_payload = temp;

            if (cose_flag_t::cose_flag_allow_debug & handle->flags) {
                handle->debug_stream.printf("kek ");
            }
        }

        if (cose_flag_t::cose_flag_auto_keygen & handle_flags) {
            if (cose_hint_flag_t::cose_hint_kty_ec & flags) {
                prng.random(temp, 12);
                kid = base64_encode(&temp[0], 4, base64_encoding_t::base64url_encoding);
                key->generate(crypto_kty_t::kty_ec, 256, kid.c_str(), crypto_use_t::use_enc);  // P-256
                kid = base64_encode(&temp[4], 4, base64_encoding_t::base64url_encoding);
                key->generate(crypto_kty_t::kty_ec, 384, kid.c_str(), crypto_use_t::use_enc);  // P384
                kid = base64_encode(&temp[8], 4, base64_encoding_t::base64url_encoding);
                key->generate(crypto_kty_t::kty_ec, 521, kid.c_str(), crypto_use_t::use_enc);  // P-521

                item.kid = kid;
                variant_set_binary_new(value, convert(kid));
                item.unprotected_map.insert(std::make_pair(cose_key_t::cose_kid, value));

                if ((cose_hint_flag_t::cose_hint_epk | cose_hint_flag_t::cose_hint_static_key | cose_hint_flag_t::cose_hint_static_kid) & flags) {
                    prng.random(temp, 12);
                    kid = base64_encode(&temp[0], 4, base64_encoding_t::base64url_encoding);
                    item.key.generate(crypto_kty_t::kty_ec, 256, kid.c_str(), crypto_use_t::use_enc);  // P-256
                    kid = base64_encode(&temp[4], 4, base64_encoding_t::base64url_encoding);
                    item.key.generate(crypto_kty_t::kty_ec, 384, kid.c_str(), crypto_use_t::use_enc);  // P-384
                    kid = base64_encode(&temp[8], 4, base64_encoding_t::base64url_encoding);
                    item.key.generate(crypto_kty_t::kty_ec, 521, kid.c_str(), crypto_use_t::use_enc);  // P-521
                }
            }

            if (cose_hint_flag_t::cose_hint_kty_okp & flags) {
                prng.random(temp, 8);
                kid = base64_encode(&temp[0], 4, base64_encoding_t::base64url_encoding);
                key->generate(crypto_kty_t::kty_okp, 25519, kid.c_str(), crypto_use_t::use_enc);  // X25519
                kid = base64_encode(&temp[4], 4, base64_encoding_t::base64url_encoding);
                key->generate(crypto_kty_t::kty_okp, 448, kid.c_str(), crypto_use_t::use_enc);  // X448

                item.kid = kid;
                variant_set_binary_new(value, convert(kid));
                item.unprotected_map.insert(std::make_pair(cose_key_t::cose_kid, value));

                if ((cose_hint_flag_t::cose_hint_epk | cose_hint_flag_t::cose_hint_static_key | cose_hint_flag_t::cose_hint_static_kid) & flags) {
                    prng.random(temp, 8);
                    kid = base64_encode(&temp[0], 4, base64_encoding_t::base64url_encoding);
                    item.key.generate(crypto_kty_t::kty_okp, 25519, kid.c_str(), crypto_use_t::use_enc);  // X25519
                    kid = base64_encode(&temp[4], 4, base64_encoding_t::base64url_encoding);
                    item.key.generate(crypto_kty_t::kty_okp, 448, kid.c_str(), crypto_use_t::use_enc);  // X448
                }
            }

            if (cose_hint_flag_t::cose_hint_kty_rsa & flags) {
                prng.random(temp, 4);
                kid = base64_encode(&temp[0], 4, base64_encoding_t::base64url_encoding);
                key->generate(crypto_kty_t::kty_rsa, 2048, kid.c_str(), crypto_use_t::use_enc);

                item.kid = kid;
                variant_set_binary_new(value, convert(kid));
                item.unprotected_map.insert(std::make_pair(cose_key_t::cose_kid, value));
            }

            if (cose_hint_flag_t::cose_hint_kty_oct & flags) {
                prng.random(temp, 4);
                kid = base64_encode(&temp[0], 4, base64_encoding_t::base64url_encoding);
                key->generate(crypto_kty_t::kty_oct, 32, kid.c_str(), crypto_use_t::use_enc);

                item.kid = kid;
                variant_set_binary_new(value, convert(kid));
                item.unprotected_map.insert(std::make_pair(cose_key_t::cose_kid, value));
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_encryption::doencrypt(cose_context_t* handle, crypto_key* key, cose_structure_t& item, binary_t const& input, binary_t& ciphertext) {
    return_t ret = errorcode_t::success;
    return_t check = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    cose_composer::composer composer;
    openssl_crypt crypt;

#if 0
    __try2 {
        ciphertext.clear();

        if (nullptr == handle || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cose_structure_t& body = handle->body;

        cose_alg_t alg = cose_alg_t::cose_unknown;
        std::string kid;
        binary_t aad;
        binary_t cek;
        binary_t iv;
        binary_t partial_iv;
        binary_t tag;
        binary_t encrypted;

        alg = body.alg;

        const hint_cose_algorithm_t* hint = advisor->hintof_cose_algorithm(alg);
        if (nullptr == hint) {
            ret = errorcode_t::request;  // study
            __leave2;
        }

        if (part) {
            kid = item.kid;
            composer.finditem(cose_key_t::cose_iv, iv, item.unprotected_map);
            composer.finditem(cose_key_t::cose_partial_iv, partial_iv, item.unprotected_map);
            cek = item.binarymap[cose_param_t::cose_param_cek];
        } else {
            cek = handle->binarymap[cose_param_t::cose_param_cek];
        }
        if (kid.empty()) {
            kid = body.kid;
        }
        if (0 == iv.size()) {
            composer.finditem(cose_key_t::cose_iv, iv, body.unprotected_map);
            if (0 == iv.size()) {
                iv = handle->binarymap[cose_param_t::cose_unsent_iv];
            }
        }
        if (0 == partial_iv.size()) {
            composer.finditem(cose_key_t::cose_partial_iv, partial_iv, body.unprotected_map);
        }

        if (iv.size() && partial_iv.size()) {
            // TEST FAILED
            // test vector wrong ?

            // RFC 8152 3.1.  Common COSE Headers Parameters
            // Partial IV
            // 1.  Left-pad the Partial IV with zeros to the length of IV.
            // 2.  XOR the padded Partial IV with the context IV.
            size_t ivsize = iv.size();
            // binary_t aligned_partial_iv;
            // binary_load(aligned_partial_iv, ivsize, &partial_iv[0], partial_iv.size());
            // for (size_t i = 0; i < ivsize; i++) {
            //     iv[i] ^= aligned_partial_iv[i];
            // }
            if (cose_flag_t::cose_flag_allow_debug & handle->flags) {
                handle->debug_flags = cose_flag_t::cose_debug_partial_iv;
            }
        }

        composer.compose_enc_structure(handle, aad);

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

        cose_group_t group = hint->group;
        if (cose_group_t::cose_group_enc_aesgcm == group) {
            // RFC 8152 10.1.  AES GCM
            ret = crypt.encrypt(hint->enc.algname, cek, iv, input, encrypted, aad, tag);
        } else if (cose_group_t::cose_group_enc_aesccm == group) {
            // RFC 8152 10.2.  AES CCM - explains about L and M parameters
            encrypt_option_t options[] = {
                {crypt_ctrl_t::crypt_ctrl_lsize, hint->enc.lsize},
                {},
            };
            ret = crypt.encrypt(hint->enc.algname, cek, iv, input, encrypted, aad, tag, options);
        } else if (cose_group_t::cose_group_enc_chacha20_poly1305 == group) {
            // size_t enc_size = 0;
            // split(body.bin_payload, enc_size, tag, hint->enc.tsize);

            // RFC 7539 ChaCha20 and Poly1305 for IETF Protocols
            // RFC 8439 ChaCha20 and Poly1305 for IETF Protocols
            //     chacha20_aead_encrypt(aad, key, iv, constant, plaintext):
            //        nonce = constant | iv
            //        otk = poly1305_key_gen(key, nonce)
            //        ciphertext = chacha20_encrypt(key, 1, nonce, plaintext)
            //        mac_data = aad | pad16(aad)
            //        mac_data |= ciphertext | pad16(ciphertext)
            //        mac_data |= num_to_8_le_bytes(aad.length)
            //        mac_data |= num_to_8_le_bytes(ciphertext.length)
            //        tag = poly1305_mac(mac_data, otk)
            //        return (ciphertext, tag)
            // RFC 8152 10.3. ChaCha20 and Poly1305

            // how to encrypt wo counter ?

            // EVP_CIPHER::(*init) chacha_init_key @openssl
            // EVP_CIPHER::(*do_cipher) chacha_cipher @openssl
            // [0..3] key setup
            // [4..11] key
            // [12..15] 1byte counter 3bytes iv
            //    \- ChaCha20_ctr32 @openssl-1.1.1, 3.0, 3.1, 3.2(alpha)

            // cf. libsodium
            // [0..3] key setup
            // [4..11] key
            // [12] counter+0   , counter
            // [13] counter+4   , iv+0
            // [14] iv+0        , iv+4
            // [15] iv+4        , iv+8
            //        \             \- crypto_aead_chacha20poly1305_ietf_encrypt/decrypt @libsodium
            //         \- crypto_aead_chacha20poly1305_encrypt/decrypt @libsodium

            ret = errorcode_t::not_supported;
        } else {
            ret = errorcode_t::request;
        }

        if (errorcode_t::success != ret) {
            __leave2;
        }

        ciphertext.insert(ciphertext.end(), encrypted.begin(), encrypted.end());
        ciphertext.insert(ciphertext.end(), tag.begin(), tag.end());
    }
    __finally2 {
        // do nothing
    }
#endif

    return ret;
}
#endif

return_t split(binary_t const& source, size_t& sizeof_ciphertext, binary_t& tag, size_t tagsize) {
    // RFC 8152 Combine the authentication tag for encryption algorithms with the ciphertext.
    return_t ret = errorcode_t::success;
    tag.clear();
    size_t size = source.size();
    if (size > tagsize) {
        const byte_t* ptr = &source[0];
        tag.insert(tag.end(), ptr + (size - tagsize), ptr + (size));
        sizeof_ciphertext = (size - tagsize);
    } else {
        ret = errorcode_t::bad_format;
    }
    return ret;
}

return_t cbor_object_encryption::decrypt(cose_context_t* handle, crypto_key* key, binary_t const& input, binary_t& output, bool& result) {
    return_t ret = errorcode_t::success;
    return_t check = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    std::set<return_t> results;
    cbor_object_signing_encryption cose;
    cbor_object_signing_encryption::parser parser;
    // cose_composer::composer composer;
    // const EVP_PKEY* pkey = nullptr;

    // RFC 8152 4.3.  Externally Supplied Data
    // RFC 8152 5.3.  How to Encrypt and Decrypt for AEAD Algorithms
    // RFC 8152 5.4.  How to Encrypt and Decrypt for AE Algorithms
    // RFC 8152 11.2.  Context Information Structure

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

        cose_structure_t& body = handle->body;
        bool do_encrypt = false;
        size_t size_multiitems = body.multiitems.size();
        if (0 == size_multiitems) {
            cose.process_keyagreement(handle, key, body, do_encrypt);
            check = dodecrypt(handle, key, body, output);
            results.insert(check);
        } else {
            std::list<cose_structure_t*>::iterator iter;
            for (iter = body.multiitems.begin(); iter != body.multiitems.end(); iter++) {
                cose_structure_t* item = *iter;

                std::list<cose_structure_t*>::iterator layered_iter;
                for (layered_iter = item->multiitems.begin(); layered_iter != item->multiitems.end(); layered_iter++) {
                    cose_structure_t* layered_item = *layered_iter;
                    cose.process_keyagreement(handle, key, *layered_item, do_encrypt);  // KEK
                }

                cose.process_keyagreement(handle, key, *item, do_encrypt);  // CEK
                check = dodecrypt(handle, key, *item, output);
                results.insert(check);
            }
        }

        if (1 == results.size()) {
            ret = *results.begin();
            if (errorcode_t::success == ret) {
                result = true;
            }
        } else {
            ret = errorcode_t::error_verify;
        }
    }
    __finally2 { cose.clear_context(handle); }
    return ret;
}

return_t cbor_object_encryption::dodecrypt(cose_context_t* handle, crypto_key* key, cose_structure_t& item, binary_t& output) {
    return_t ret = errorcode_t::success;
    return_t check = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    cbor_object_signing_encryption::parser parser;
    // cose_composer::composer composer;
    openssl_crypt crypt;

    __try2 {
        if (nullptr == handle || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cose_structure_t& body = handle->body;

        cose_alg_t alg = cose_alg_t::cose_unknown;
        std::string kid;
        binary_t aad;
        binary_t cek;
        binary_t iv;
        binary_t partial_iv;
        binary_t tag;

        alg = body.alg;

        const hint_cose_algorithm_t* hint = advisor->hintof_cose_algorithm(alg);
        if (nullptr == hint) {
            ret = errorcode_t::request;  // study
            __leave2;
        }

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
            size_t ivsize = iv.size();
            // binary_t aligned_partial_iv;
            // binary_load(aligned_partial_iv, ivsize, &partial_iv[0], partial_iv.size());
            // for (size_t i = 0; i < ivsize; i++) {
            //     iv[i] ^= aligned_partial_iv[i];
            // }
            if (cose_flag_t::cose_flag_allow_debug & handle->flags) {
                handle->debug_flags = cose_flag_t::cose_debug_partial_iv;
            }
        }

        parser.compose_enc_structure(handle, aad);

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

        cose_group_t group = hint->group;
        if (cose_group_t::cose_group_enc_aesgcm == group) {
            size_t enc_size = 0;
            split(body.bin_payload, enc_size, tag, hint->enc.tsize);

            // RFC 8152 10.1.  AES GCM
            ret = crypt.decrypt(hint->enc.algname, cek, iv, &body.bin_payload[0], enc_size, output, aad, tag);

        } else if (cose_group_t::cose_group_enc_aesccm == group) {
            size_t enc_size = 0;
            split(body.bin_payload, enc_size, tag, hint->enc.tsize);

            // RFC 8152 10.2.  AES CCM - explains about L and M parameters
            encrypt_option_t options[] = {
                {crypt_ctrl_t::crypt_ctrl_lsize, hint->enc.lsize},
                {},
            };
            ret = crypt.decrypt(hint->enc.algname, cek, iv, &body.bin_payload[0], enc_size, output, aad, tag, options);
        } else if (cose_group_t::cose_group_enc_chacha20_poly1305 == group) {
            // RFC 7539 ChaCha20 and Poly1305 for IETF Protocols
            // RFC 8439 ChaCha20 and Poly1305 for IETF Protocols
            //     chacha20_aead_encrypt(aad, key, iv, constant, plaintext):
            //        nonce = constant | iv
            //        otk = poly1305_key_gen(key, nonce)
            //        ciphertext = chacha20_encrypt(key, 1, nonce, plaintext)
            //        mac_data = aad | pad16(aad)
            //        mac_data |= ciphertext | pad16(ciphertext)
            //        mac_data |= num_to_8_le_bytes(aad.length)
            //        mac_data |= num_to_8_le_bytes(ciphertext.length)
            //        tag = poly1305_mac(mac_data, otk)
            //        return (ciphertext, tag)
            // RFC 8152 10.3. ChaCha20 and Poly1305

            // how to encrypt wo counter ?

            // EVP_CIPHER::(*init) chacha_init_key @openssl
            // EVP_CIPHER::(*do_cipher) chacha_cipher @openssl
            // [0..3] key setup
            // [4..11] key
            // [12..15] 1byte counter 3bytes iv
            //    \- ChaCha20_ctr32 @openssl-1.1.1, 3.0, 3.1, 3.2(alpha)

            // cf. libsodium
            // [0..3] key setup
            // [4..11] key
            // [12] counter+0   , counter
            // [13] counter+4   , iv+0
            // [14] iv+0        , iv+4
            // [15] iv+4        , iv+8
            //        \             \- crypto_aead_chacha20poly1305_ietf_encrypt/decrypt @libsodium
            //         \- crypto_aead_chacha20poly1305_encrypt/decrypt @libsodium

            ret = errorcode_t::not_supported;
        } else {
            ret = errorcode_t::request;
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

}  // namespace crypto
}  // namespace hotplace
