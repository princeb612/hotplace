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

#include <hotplace/sdk/crypto/cose/cbor_object_encryption.hpp>
#include <hotplace/sdk/io/cbor/cbor_array.hpp>
#include <hotplace/sdk/io/cbor/cbor_data.hpp>
#include <hotplace/sdk/io/cbor/cbor_encode.hpp>
#include <hotplace/sdk/io/cbor/cbor_map.hpp>
#include <hotplace/sdk/io/cbor/cbor_publisher.hpp>
#include <hotplace/sdk/io/cbor/cbor_reader.hpp>

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

return_t compose_enc_structure(binary_t& enc_structure, uint8 tag, binary_t const& body_protected, binary_t const& aad) {
    return_t ret = errorcode_t::success;
    cbor_encode encoder;
    cbor_publisher pub;
    cbor_array* root = nullptr;

    __try2 {
        enc_structure.clear();

        root = new cbor_array();

        if (cbor_tag_t::cose_tag_encrypt == tag) {
            *root << new cbor_data("Encrypt");
        } else if (cbor_tag_t::cose_tag_encrypt0 == tag) {
            *root << new cbor_data("Encrypt0");
        } else {
            ret = errorcode_t::request;
            __leave2;
        }

        *root << new cbor_data(body_protected);
        *root << new cbor_data(aad);

        pub.publish(root, &enc_structure);
    }
    __finally2 {
        if (root) {
            root->release();
        }
    }
    return ret;
}

return_t cbor_object_encryption::decrypt(cose_context_t* handle, crypto_key* key, binary_t const& input, bool& result) {
    return_t ret = errorcode_t::not_supported;
#if 0  // studying... just sketch
    return_t ret = errorcode_t::success;
    return_t check = errorcode_t::success;
    std::set<bool> results;
    cbor_object_signing_encryption::composer composer;
    EVP_PKEY* pkey = nullptr;

    __try2 {
        ret = errorcode_t::verify;
        result = false;

        if (nullptr == handle || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        composer.parse(handle, cbor_tag_t::cose_tag_encrypt, input);

        const char* k = nullptr;

        binary_t aad;
        size_t size_subitems = handle->subitems.size();
        std::list<cose_parts_t>::iterator iter;
        for (iter = handle->subitems.begin(); iter != handle->subitems.end(); iter++) {
            cose_parts_t& item = *iter;
            int alg = 0;
            std::string kid;
            return_t check = errorcode_t::success;
            composer.finditem(cose_key_t::cose_alg, alg, item.protected_map);
            composer.finditem(cose_key_t::cose_kid, kid, item.unprotected_map);
            if (kid.size()) {
                k = kid.c_str();
            }

            pkey = key->find(kid.c_str(), crypto_kty_t::kty_ec);
            if (cose_alg_t::cose_ecdh_es_hkdf_256 == alg) {
            else if (cose_alg_t::cose_ecdh_es_hkdf_256 == alg) {
                binary_t secret;
                binary_t salt;
                dh_key_agreement(pkey, item.epk, secret);
                binary_t derived;
                salt.resize(256 >> 3);
                // kdf_hkdf(derived, 256 >> 3, secret, salt, convert(""), hash_algorithm_t::sha2_256);
                // compose_enc_structure(aad, handle->tag, item.bin_protected, convert(""));
                binary_t iv;
                // int body_alg = 0;
                // check = composer.finditem(cose_key_t::cose_alg, body_alg, handle->body.protected_map);

                binary_t decrypted;
                openssl_crypt crypt;
                crypt_context_t* crypt_handle = nullptr;
                // crypt.open(&crypt_handle, crypt_algorithm_t::aes256, crypt_mode_t::gcm, derived, iv);
                // check = crypt.decrypt2 (crypt_handle, handle->payload, decrypted, aad, tag);
                // crypt.close(crypt_handle);

                // results.insert((errorcode_t::success == check) ? true : false);

                basic_stream bs;
                dump_memory(secret, &bs);
                printf("secret\n%s\n", bs.c_str());
                dump_memory(derived, &bs);
                printf("derived\n%s\n", bs.c_str());
                dump_memory(decrypted, &bs);
                printf("decrypted\n%s\n", bs.c_str());
            }
        }

        if ((1 == results.size()) && (true == *results.begin())) {
            result = true;
            ret = errorcode_t::success;
        }
    }
    __finally2 {
        // do nothing
    }
#endif
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
