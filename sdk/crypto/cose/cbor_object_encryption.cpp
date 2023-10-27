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
#include <sdk/crypto/basic/openssl_chacha20.hpp>
#include <sdk/crypto/basic/openssl_crypt.hpp>
#include <sdk/crypto/basic/openssl_ecdh.hpp>
#include <sdk/crypto/basic/openssl_hash.hpp>
#include <sdk/crypto/basic/openssl_kdf.hpp>
#include <sdk/crypto/basic/openssl_sign.hpp>
#include <sdk/crypto/cose/cbor_object_encryption.hpp>
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

return_t cbor_object_encryption::encrypt(cose_context_t* handle, crypto_key* key, cose_alg_t method, binary_t const& input, binary_t& output) {
    return_t ret = errorcode_t::success;

    return ret;
}

return_t cbor_object_encryption::encrypt(cose_context_t* handle, crypto_key* key, std::list<cose_alg_t> methods, binary_t const& input, binary_t& output) {
    return_t ret = errorcode_t::success;

    return ret;
}

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

return_t cbor_object_encryption::dodecrypt(cose_context_t* handle, crypto_key* key, binary_t& output) {
    return_t ret = errorcode_t::success;
    return_t check = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    cbor_object_signing_encryption::composer composer;
    int enc_alg = 0;
    openssl_crypt crypt;
    // openssl_hash hash;
    crypt_context_t* crypt_handle = nullptr;
    // hash_context_t* hash_handle = nullptr;

    __try2 {
        if (nullptr == handle || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        check = composer.finditem(cose_key_t::cose_alg, enc_alg, handle->body.protected_map);
        if (errorcode_t::success != check) {
            check = composer.finditem(cose_key_t::cose_alg, enc_alg, handle->body.unprotected_map);
        }

        const hint_cose_algorithm_t* enc_hint = advisor->hintof_cose_algorithm((cose_alg_t)enc_alg);

        maphint<cose_param_t, binary_t> hint(handle->binarymap);

        binary_t iv;

        composer.finditem(cose_key_t::cose_iv, iv, handle->body.unprotected_map);
        if (0 == iv.size()) {
            iv = handle->binarymap[cose_param_t::cose_unsent_iv];
        }
        if (iv.size()) {
            // TEST FAILED
            // test vector wrong ?

            // RFC 8152 3.1.  Common COSE Headers Parameters
            // Partial IV
            // 1.  Left-pad the Partial IV with zeros to the length of IV.
            // 2.  XOR the padded Partial IV with the context IV.
            size_t ivsize = iv.size();
            binary_t partial_iv;
            composer.finditem(cose_key_t::cose_partial_iv, partial_iv, handle->body.unprotected_map);
            if (partial_iv.size()) {
                // binary_t aligned_partial_iv;
                // binary_load(aligned_partial_iv, ivsize, &partial_iv[0], partial_iv.size());
                // for (size_t i = 0; i < ivsize; i++) {
                //     iv[i] ^= aligned_partial_iv[i];
                // }
#if defined DEBUG
                handle->debug_flag = code_debug_flag_t::cose_debug_partial_iv;
#endif
            }
        }

        const EVP_PKEY* pkey = nullptr;
        binary_t cek;
        hint.find(cose_param_t::cose_param_cek, &cek);
        uint8 cbor_tag = handle->cbor_tag;
        if (0 == cek.size()) {
            ret = errorcode_t::no_data;
            __leave2;
        }

        binary_t authenticated_data = handle->binarymap[cose_param_t::cose_param_aad];

        binary_t tag;

        cose_group_t group = enc_hint->group;
        if (cose_group_t::cose_group_aesgcm == group) {
            size_t enc_size = 0;
            split(handle->payload, enc_size, tag, enc_hint->param.tsize);

            // RFC 8152 10.1.  AES GCM
            crypt.open(&crypt_handle, enc_hint->param.algname, cek, iv);
            ret = crypt.decrypt2(crypt_handle, &handle->payload[0], enc_size, output, &authenticated_data, &tag);
            crypt.close(crypt_handle);

        } else if (cose_group_t::cose_group_aesccm == group) {
            size_t enc_size = 0;
            split(handle->payload, enc_size, tag, enc_hint->param.tsize);

            // RFC 8152 10.2.  AES CCM - explains about L and M parameters
            crypt.open(&crypt_handle, enc_hint->param.algname, cek, iv);
            crypt.set(crypt_handle, crypt_ctrl_t::crypt_ctrl_lsize, enc_hint->param.lsize);
            ret = crypt.decrypt2(crypt_handle, &handle->payload[0], enc_size, output, &authenticated_data, &tag);
            crypt.close(crypt_handle);
        } else if (cose_group_t::cose_group_chacha20_poly1305 == group) {
            // TEST FAILED - counter ??
            size_t enc_size = 0;
            split(handle->payload, enc_size, tag, enc_hint->param.tsize);

            uint32 counter = 0;
            binary_t chacha20iv;
            openssl_chacha20_iv(chacha20iv, counter, iv);
            // RFC 8152 10.3. ChaCha20 and Poly1305
            crypt.open(&crypt_handle, enc_hint->param.algname, cek, chacha20iv);
            ret = crypt.decrypt2(crypt_handle, &handle->payload[0], enc_size, output, &authenticated_data, &tag);
            crypt.close(crypt_handle);
#if defined DEBUG
            handle->debug_flag |= cose_debug_chacha20_poly1305;
#endif
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t cbor_object_encryption::decrypt(cose_context_t* handle, crypto_key* key, binary_t const& input, binary_t& output, bool& result) {
    return_t ret = errorcode_t::success;
    return_t check = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    std::set<bool> results;
    cbor_object_signing_encryption::composer composer;
    // const EVP_PKEY* pkey = nullptr;

    // RFC 8152 4.3.  Externally Supplied Data
    // RFC 8152 5.3.  How to Encrypt and Decrypt for AEAD Algorithms
    // RFC 8152 5.4.  How to Encrypt and Decrypt for AE Algorithms
    // RFC 8152 11.2.  Context Information Structure

    __try2 {
        cbor_object_signing_encryption::clear_context(handle);
        result = false;

        if (nullptr == handle || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = composer.parse(handle, input);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // AAD_hex
        binary_t authenticated_data;
        composer.compose_enc_structure(handle, authenticated_data);

        // too many parameters... handle w/ map
        handle->binarymap[cose_param_t::cose_param_aad] = authenticated_data;

        size_t size_multiitems = handle->multiitems.size();
        if (0 == size_multiitems) {
            int alg = 0;
            std::string kid;
            const char* k = nullptr;

            check = composer.finditem(cose_key_t::cose_alg, alg, handle->body.protected_map);
            if (errorcode_t::success != check) {
                check = composer.finditem(cose_key_t::cose_alg, alg, handle->body.unprotected_map);
            }
            composer.finditem(cose_key_t::cose_kid, kid, handle->body.protected_map);
            if (kid.size()) {
                k = kid.c_str();
            }

            const hint_cose_algorithm_t* enc_hint = advisor->hintof_cose_algorithm((cose_alg_t)alg);

            const EVP_PKEY* pkey = nullptr;
            if (k) {
                pkey = key->find(k, enc_hint->kty);
            } else {
                pkey = key->select(kid, enc_hint->kty);
            }

            if (nullptr == pkey) {
#if defined DEBUG
                handle->debug_flag |= cose_debug_notfound_key;
#endif
                ret = errorcode_t::not_found;
                __leave2;
            }

            crypto_kty_t kty;
            binary_t cek;
            key->get_privkey(pkey, kty, cek, true);
            handle->binarymap[cose_param_t::cose_param_cek] = cek;

            check = dodecrypt(handle, key, output);

            results.insert((errorcode_t::success == check) ? true : false);
        } else {
            std::list<cose_parts_t>::iterator iter;
            for (iter = handle->multiitems.begin(); iter != handle->multiitems.end(); iter++) {
                cose_parts_t& item = *iter;

                // cek into handle->binarymap[cose_param_t::cose_param_cek]
                cbor_object_signing_encryption::process_recipient(handle, key, &item);

                check = dodecrypt(handle, key, output);

                results.insert((errorcode_t::success == check) ? true : false);
            }
        }

        if ((1 == results.size()) && (true == *results.begin())) {
            result = true;
            ret = errorcode_t::success;
        } else {
            ret = errorcode_t::error_verify;
        }
    }
    __finally2 { cbor_object_signing_encryption::clear_context(handle); }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
