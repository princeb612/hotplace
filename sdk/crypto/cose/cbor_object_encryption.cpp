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

return_t cbor_object_encryption::encrypt(cose_context_t* handle, crypto_key* key, cose_alg_t method, binary_t const& input, binary_t const& external,
                                         binary_t& output) {
    return_t ret = errorcode_t::success;

    return ret;
}

return_t cbor_object_encryption::encrypt(cose_context_t* handle, crypto_key* key, std::list<cose_alg_t> methods, binary_t const& input,
                                         binary_t const& external, binary_t& output) {
    return_t ret = errorcode_t::success;

    return ret;
}

return_t cbor_object_encryption::compose_enc_structure(binary_t& authenticated_data, uint8 tag, binary_t const& body_protected, binary_t const& external) {
    return_t ret = errorcode_t::success;
    cbor_encode encoder;
    cbor_publisher pub;
    cbor_array* root = nullptr;

    __try2 {
        authenticated_data.clear();

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
        *root << new cbor_data(external);

        pub.publish(root, &authenticated_data);
    }
    __finally2 {
        if (root) {
            root->release();
        }
    }
    return ret;
}

return_t cbor_object_encryption::decrypt(cose_context_t* handle, crypto_key* key, binary_t const& input, binary_t const& external, bool& result) {
    return_t ret = errorcode_t::not_supported;
    return_t check = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    std::set<bool> results;
    cbor_object_signing_encryption::composer composer;
    EVP_PKEY* pkey = nullptr;

    // RFC 8152 4.3.  Externally Supplied Data
    // RFC 8152 5.3.  How to Encrypt and Decrypt for AEAD Algorithms
    // RFC 8152 5.4.  How to Encrypt and Decrypt for AE Algorithms

    __try2 {
        ret = errorcode_t::verify;
        result = false;

        if (nullptr == handle || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        composer.parse(handle, cbor_tag_t::cose_tag_encrypt, input);

        const char* k = nullptr;

        size_t size_subitems = handle->subitems.size();
        std::list<cose_parts_t>::iterator iter;
        for (iter = handle->subitems.begin(); iter != handle->subitems.end(); iter++) {
            cose_parts_t& item = *iter;

            binary_t authenticated_data;
            binary_t decrypted;
            binary_t derived;
            binary_t iv;
            binary_t salt;
            binary_t secret;
            openssl_crypt crypt;
            crypt_context_t* crypt_handle = nullptr;

            compose_enc_structure(authenticated_data, handle->tag, handle->body.bin_protected, external);

            int alg = 0;
            std::string kid;
            return_t check = errorcode_t::success;
            composer.finditem(cose_key_t::cose_alg, alg, item.protected_map);
            composer.finditem(cose_key_t::cose_kid, kid, item.unprotected_map);
            if (kid.size()) {
                k = kid.c_str();
            }

            const hint_cose_algorithm_t* hint = advisor->hintof_cose_algorithm((cose_alg_t)alg);
            if (nullptr == hint) {
                continue;
            }

            pkey = key->find(k, hint->kty);
            if (nullptr == pkey) {
                continue;
            }

            cose_group_t group = hint->group;

            if (cose_group_t::cose_group_aeskw == group) {
            } else if (cose_group_t::cose_group_direct == group) {
            } else if (cose_group_t::cose_group_ecdsa == group) {
            } else if (cose_group_t::cose_group_eddsa == group) {
            } else if (cose_group_t::cose_group_direct_hkdf_sha == group) {
            } else if (cose_group_t::cose_group_direct_hkdf_aes == group) {
            } else if (cose_group_t::cose_group_sha == group) {
            } else if (cose_group_t::cose_group_ecdh_es_hkdf == group) {
                dh_key_agreement(pkey, item.epk, secret);
                hash_algorithm_t hashalg;
                int dlen = 0;
                if (cose_ecdh_es_hkdf_256 == alg) {
                    dlen = 256 >> 3;
                    hashalg = hash_algorithm_t::sha2_256;
                } else if (cose_ecdh_es_hkdf_512 == alg) {
                    dlen = 512 >> 3;
                    hashalg = hash_algorithm_t::sha2_512;
                }
                salt.resize(dlen);
                kdf_hkdf(derived, dlen, authenticated_data, salt, convert(""), hashalg);
            } else if (cose_group_t::cose_group_ecdh_ss_hkdf == group) {
            } else if (cose_group_t::cose_group_ecdh_es_aeskw == group) {
                dh_key_agreement(pkey, item.epk, secret);
            } else if (cose_group_t::cose_group_ecdh_ss_aeskw == group) {
            } else if (cose_group_t::cose_group_rsassa_pss == group) {
            } else if (cose_group_t::cose_group_rsa_oaep == group) {
            } else if (cose_group_t::cose_group_rsassa_pkcs15 == group) {
            } else if (cose_group_t::cose_group_aesgcm == group) {
            } else if (cose_group_t::cose_group_hmac == group) {
            } else if (cose_group_t::cose_group_aesccm == group) {
            } else if (cose_group_t::cose_group_aescbc_mac == group) {
            } else if (cose_group_t::cose_group_chacha20 == group) {
            } else if (cose_group_t::cose_group_iv == group) {
            }

            basic_stream bs;
            dump_memory(authenticated_data, &bs);
            printf("\e[35mauthenticated_data\n%s\n%s\n\e[0m", bs.c_str(), base16_encode(authenticated_data).c_str());
            dump_memory(secret, &bs);
            printf("secret\n%s\n", bs.c_str());
            dump_memory(derived, &bs);
            printf("derived\n%s\n", bs.c_str());
            dump_memory(decrypted, &bs);
            printf("decrypted\n%s\n", bs.c_str());
        }

        if ((1 == results.size()) && (true == *results.begin())) {
            result = true;
            ret = errorcode_t::success;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
