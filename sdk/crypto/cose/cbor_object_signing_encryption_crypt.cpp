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

return_t cbor_object_signing_encryption::encrypt(cose_context_t* handle, crypto_key* key, std::list<cose_alg_t>& algs, const binary_t& input,
                                                 binary_t& output) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = preprocess(handle, key, algs, crypt_category_t::crypt_category_crypt, input);
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

return_t cbor_object_signing_encryption::encrypt(cose_context_t* handle, crypto_key* key, const binary_t& input, binary_t& output) {
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

return_t cbor_object_signing_encryption::decrypt(cose_context_t* handle, crypto_key* key, const binary_t& input, binary_t& output, bool& result) {
    return_t ret = errorcode_t::success;
    ret = process(handle, key, input, output, cose_mode_t::cose_mode_recv);
    return ret;
}

return_t cbor_object_signing_encryption::compose_enc_context(cose_context_t* handle, cose_layer* layer, binary_t& aad) {
    return_t ret = errorcode_t::success;
    cbor_encode encoder;
    cbor_publisher pub;
    cbor_array* root = nullptr;

    // 5.3.  How to Encrypt and Decrypt for AEAD Algorithms
    // Enc_structure = [
    //     context : "Encrypt" / "Encrypt0" / "Enc_Recipient" /
    //         "Mac_Recipient" / "Rec_Recipient",
    //     protected : empty_or_serialized_map,
    //     external_aad : bstr
    // ]

    __try2 {
        aad.clear();

        cose_layer& body = handle->composer->get_layer();

        size_t size_recipients = body.get_recipients().size();
        binary_t external;
        binary_t payload;
        layer->finditem(cose_param_t::cose_external, external, cose_scope::cose_scope_unsent);
        body.get_payload().get(payload);

        /**
         * cose_tag_encrypt     protected, unprotected_map, ciphertext, [+recipient]
         * cose_tag_encrypt0    protected, unprotected_map, ciphertext
         */

        root = new cbor_array();

        if (size_recipients) {
            *root << new cbor_data("Encrypt");
        } else {
            *root << new cbor_data("Encrypt0");
        }

        *root << body.get_protected().cbor() << new cbor_data(external);

        pub.publish(root, &aad);
    }
    __finally2 {
        if (root) {
            root->release();
        }
    }
    return ret;
}

return_t split(const binary_t& source, size_t& sizeof_ciphertext, binary_t& tag, size_t tagsize) {
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

return_t cbor_object_signing_encryption::docrypt(cose_context_t* handle, crypto_key* key, cose_layer* layer, cose_mode_t mode) {
    return_t ret = errorcode_t::success;
    return_t check = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    openssl_crypt crypt;

    __try2 {
        if (nullptr == handle || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cose_layer& body = handle->composer->get_layer();
        cose_layer* source = layer->get_upperlayer2();
        cose_alg_t alg = layer->get_algorithm();
        std::string kid = layer->get_kid();

        binary_t aad;
        binary_t cek;
        binary_t iv;
        binary_t partial_iv;
        binary_t tag;
        binary_t encrypted;
        binary_t output;
        binary_t payload;
        binary_t input;
        binary_t ciphertext;

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

        if (istraceable()) {
            basic_stream dbs;
            dbs.println("docrypt alg %i (%s)", alg, hint->name);
            trace_debug_event(category_crypto, crypto_event_cose, &dbs);
        }

        if (iv.size() && partial_iv.size()) {
            // TEST FAILED - TODO

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
            handle->debug_flags |= cose_flag_t::cose_debug_partial_iv;
        }

        compose_enc_context(handle, layer, aad);

        const EVP_PKEY* pkey = nullptr;
        if (kid.size()) {
            pkey = key->find(kid.c_str(), hint->kty);
        } else {
            std::string k;
            pkey = key->select(k, hint->kty);
        }

        if (mode) {
            body.get_params().finditem(cose_param_t::cose_param_plaintext, input);
        } else {
            body.get_payload().get(payload);
        }

        cose_group_t group = hint->group;
        if (cose_group_t::cose_group_enc_aesgcm == group) {
            if (mode) {
                ret = crypt.encrypt(hint->enc.algname, cek, iv, input, ciphertext, aad, tag);
            } else {
                size_t enc_size = 0;
                split(payload, enc_size, tag, hint->enc.tsize);

                // RFC 8152 10.1.  AES GCM
                ret = crypt.decrypt(hint->enc.algname, cek, iv, &payload[0], enc_size, output, aad, tag);
            }
        } else if (cose_group_t::cose_group_enc_aesccm == group) {
            // RFC 8152 10.2.  AES CCM - explains about L and M parameters
            encrypt_option_t options[] = {
                {crypt_ctrl_t::crypt_ctrl_tsize, hint->enc.tsize},
                {crypt_ctrl_t::crypt_ctrl_lsize, hint->enc.lsize},
                {},
            };
            if (mode) {
                ret = crypt.encrypt(hint->enc.algname, cek, iv, input, ciphertext, aad, tag, options);
            } else {
                size_t enc_size = 0;
                split(payload, enc_size, tag, hint->enc.tsize);

                ret = crypt.decrypt(hint->enc.algname, cek, iv, &payload[0], enc_size, output, aad, tag, options);
            }
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
            ret = errorcode_t::bad_request;
        }

        if (istraceable()) {
            // std::function<void (const char* text, binary_t& bin)> dump;
            auto dump = [&](const char* text, binary_t& bin) -> void {
                if (bin.size()) {
                    basic_stream dbs;
                    dbs.println("  %-10s %s", text ? text : "", base16_encode(bin).c_str());
                    trace_debug_event(category_crypto, crypto_event_cose, &dbs);
                }
            };

            dump("aad", aad);
            dump("cek", cek);
            dump("iv", iv);
            dump("output", output);
        }

        if (errorcode_t::success != ret) {
            __leave2;
        }

        if (mode) {
            output.insert(output.end(), ciphertext.begin(), ciphertext.end());
            output.insert(output.end(), tag.begin(), tag.end());
            body.get_payload().set(output);
        } else {
            layer->setparam(cose_param_t::cose_param_ciphertext, output);
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

}  // namespace crypto
}  // namespace hotplace
