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
#include <hotplace/sdk/crypto/basic/openssl_crypt.hpp>
#include <hotplace/sdk/crypto/basic/openssl_ecdh.hpp>
#include <hotplace/sdk/crypto/basic/openssl_hash.hpp>
#include <hotplace/sdk/crypto/basic/openssl_kdf.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sign.hpp>
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

return_t cbor_object_encryption::compose_enc_structure(binary_t& authenticated_data, uint8 tag, binary_t const& body_protected, binary_t const& external) {
    return_t ret = errorcode_t::success;
    cbor_encode encoder;
    cbor_publisher pub;
    cbor_array* root = nullptr;

    // Enc_structure = [
    //     context : "Encrypt" / "Encrypt0" / "Enc_Recipient" /
    //         "Mac_Recipient" / "Rec_Recipient",
    //     protected : empty_or_serialized_map,
    //     external_aad : bstr
    // ]

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

        *root << new cbor_data(body_protected) << new cbor_data(external);

        pub.publish(root, &authenticated_data);
    }
    __finally2 {
        if (root) {
            root->release();
        }
    }
    return ret;
}

cbor_data* kdf_context_item(cose_key_t id, cose_parts_t* source, cose_variantmap_t* info) {
    return_t ret = errorcode_t::success;
    cbor_object_signing_encryption::composer composer;
    binary_t bin;
    ret = composer.finditem(id, bin, *info);
    if (errorcode_t::success != ret) {
        composer.finditem(id, bin, source->unprotected_map);
    }
    cbor_data* data = nullptr;
    if (bin.size()) {
        data = new cbor_data(bin);
    } else {
        data = new cbor_data();  // null(F6)
    }
    return data;
}

return_t compose_kdf_context(cose_context_t* handle, cose_parts_t* source, binary_t& context) {
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

    __try2 {
        if (nullptr == handle || nullptr == source) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        int algid = 0;
        int recp_alg = 0;
        cbor_object_signing_encryption::composer composer;

        composer.finditem(cose_key_t::cose_alg, recp_alg, source->protected_map);
        switch (recp_alg) {
            case cose_ecdh_es_a128kw:
            case cose_ecdh_ss_a128kw:
                algid = cose_aes_128_kw;  // -3
                break;
            case cose_ecdh_es_a192kw:
            case cose_ecdh_ss_a192kw:
                algid = cose_aes_192_kw;  // -4
                break;
            case cose_ecdh_es_a256kw:
            case cose_ecdh_ss_a256kw:
                algid = cose_aes_256_kw;  // -5
                break;
            default:
                composer.finditem(cose_key_t::cose_alg, algid, handle->body.protected_map);
                break;
        }

        int keylen = 0;
        switch (algid) {
            case cose_aes_128_kw:
            case cose_aes_128_gcm:
            case cose_aes_cbc_mac_128_64:
            case cose_aes_cbc_mac_128_128:
            case cose_aes_ccm_16_64_128:
            case cose_aes_ccm_64_64_128:
            case cose_aes_ccm_16_128_128:
            case cose_aes_ccm_64_128_128:
            case cose_direct_hkdf_sha_256:
            case cose_direct_hkdf_aes_128:
            case cose_ecdh_es_hkdf_256:
            case cose_ecdh_ss_hkdf_256:
            case cose_hs256_64:
            case cose_hs256:
                keylen = 128;
                break;
            case cose_aes_192_kw:
            case cose_aes_192_gcm:
            case cose_hs384:
                keylen = 192;
                break;
            case cose_aes_256_kw:
            case cose_aes_256_gcm:
            case cose_aes_cbc_mac_256_64:
            case cose_aes_cbc_mac_256_128:
            case cose_aes_ccm_16_64_256:
            case cose_aes_ccm_64_64_256:
            case cose_aes_ccm_16_128_256:
            case cose_aes_ccm_64_128_256:
            case cose_direct_hkdf_sha_512:
            case cose_direct_hkdf_aes_256:
            case cose_ecdh_es_hkdf_512:
            case cose_ecdh_ss_hkdf_512:
            case cose_hs512:
                keylen = 256;
                break;
            default:
                ret = errorcode_t::not_supported;  // studying
                break;
        }

        if (0 == keylen) {
            printf("algid %i\n", algid);
            throw;  // studying
        }

        root = new cbor_array();
        *root << new cbor_data(algid) << new cbor_array() << new cbor_array() << new cbor_array();
        cbor_array* partyu = (cbor_array*)(*root)[1];
        cbor_array* partyv = (cbor_array*)(*root)[2];
        cbor_array* pub = (cbor_array*)(*root)[3];
        // PartyUInfo
        {
            *partyu << kdf_context_item(cose_key_t::cose_partyu_id, source, &handle->partyu)
                    << kdf_context_item(cose_key_t::cose_partyu_nonce, source, &handle->partyu)
                    << kdf_context_item(cose_key_t::cose_partyu_other, source, &handle->partyu);
        }
        // PartyVInfo
        {
            *partyv << kdf_context_item(cose_key_t::cose_partyv_id, source, &handle->partyv)
                    << kdf_context_item(cose_key_t::cose_partyv_nonce, source, &handle->partyv)
                    << kdf_context_item(cose_key_t::cose_partyv_other, source, &handle->partyv);
        }
        // SuppPubInfo
        {
            *pub << new cbor_data(keylen) << new cbor_data(source->bin_protected);
            if (handle->pub.size()) {
                *pub << new cbor_data(handle->pub);
            }
        }
        // SuppPrivInfo
        {
            if (handle->priv.size()) {
                *root << new cbor_data(handle->priv);
            }
        }

        cbor_publisher publisher;
        publisher.publish(root, &context);
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
    return_t check = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    std::set<bool> results;
    cbor_object_signing_encryption::composer composer;
    EVP_PKEY* pkey = nullptr;

    // RFC 8152 4.3.  Externally Supplied Data
    // RFC 8152 5.3.  How to Encrypt and Decrypt for AEAD Algorithms
    // RFC 8152 5.4.  How to Encrypt and Decrypt for AE Algorithms
    // RFC 8152 11.2.  Context Information Structure

    __try2 {
        cbor_object_signing_encryption::clear_context(handle);
        ret = errorcode_t::verify;
        result = false;

        if (nullptr == handle || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        composer.parse(handle, cbor_tag_t::cose_tag_encrypt, input);

        // AAD_hex
        binary_t authenticated_data;
        compose_enc_structure(authenticated_data, handle->tag, handle->body.bin_protected, handle->external);

        const char* k = nullptr;

        size_t size_subitems = handle->subitems.size();
        std::list<cose_parts_t>::iterator iter;
        for (iter = handle->subitems.begin(); iter != handle->subitems.end(); iter++) {
            cose_parts_t& item = *iter;

            binary_t context;
            binary_t decrypted;
            binary_t cek;
            binary_t iv;
            binary_t salt;
            binary_t secret;
            openssl_crypt crypt;
            openssl_hash hash;
            crypt_context_t* crypt_handle = nullptr;
            hash_context_t* hash_handle = nullptr;

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

            // reversing "AAD_hex", "CEK_hex", "Context_hex" from https://github.com/cose-wg/Examples

            if (cose_group_t::cose_group_aeskw == group) {
            } else if (cose_group_t::cose_group_direct == group) {
                // RFC 8152 12.1. Direct Encryption
            } else if (cose_group_t::cose_group_ecdsa == group) {
                // RFC 8152 8.1. ECDSA
            } else if (cose_group_t::cose_group_eddsa == group) {
                // RFC 8152 8.2. Edwards-Curve Digital Signature Algorithms (EdDSAs)
            } else if (cose_group_t::cose_group_direct_hkdf_sha == group) {
                // RFC 8152 12.1.2.  Direct Key with KDF
                compose_kdf_context(handle, &item, context);
                composer.finditem(cose_key_t::cose_salt, salt, item.unprotected_map);
            } else if (cose_group_t::cose_group_direct_hkdf_aes == group) {
                // RFC 8152 11.1.  HMAC-Based Extract-and-Expand Key Derivation Function (HKDF)
                compose_kdf_context(handle, &item, context);
            } else if (cose_group_t::cose_group_sha == group) {
            } else if (cose_group_t::cose_group_ecdh_es_hkdf == group) {
                // RFC 8152 12.4.1. ECDH
                // RFC 8152 11.1.  HMAC-Based Extract-and-Expand Key Derivation Function (HKDF)
                dh_key_agreement(pkey, item.epk, secret);
                compose_kdf_context(handle, &item, context);
                salt.resize(hint->kdf_dlen);
                kdf_hkdf(cek, hint->kdf_dlen, secret, salt, context, hint->hkdf_prf);
            } else if (cose_group_t::cose_group_ecdh_ss_hkdf == group) {
                // RFC 8152 12.4.1. ECDH
                // RFC 8152 11.1.  HMAC-Based Extract-and-Expand Key Derivation Function (HKDF)
                std::string static_keyid;
                composer.finditem(cose_key_t::cose_static_key_id, static_keyid, item.unprotected_map);
                EVP_PKEY* epk = key->find(static_keyid.c_str(), hint->kty);
                dh_key_agreement(pkey, epk, secret);
                compose_kdf_context(handle, &item, context);
                salt.resize(hint->kdf_dlen);
                kdf_hkdf(cek, hint->kdf_dlen, secret, salt, context, hint->hkdf_prf);
            } else if (cose_group_t::cose_group_ecdh_es_aeskw == group) {
                // RFC 8152 12.5.1. ECDH
                // RFC 8152 12.2.1. AES Key Wrap
                dh_key_agreement(pkey, item.epk, secret);
                compose_kdf_context(handle, &item, context);
            } else if (cose_group_t::cose_group_ecdh_ss_aeskw == group) {
                // RFC 8152 12.5.1. ECDH
                // RFC 8152 12.2.1. AES Key Wrap
                compose_kdf_context(handle, &item, context);
                std::string static_keyid;
                composer.finditem(cose_key_t::cose_static_key_id, static_keyid, item.unprotected_map);
                EVP_PKEY* epk = key->find(static_keyid.c_str(), hint->kty);
                dh_key_agreement(pkey, epk, secret);
                // 12.5.  Key Agreement with Key Wrap
                // encryptedKey = KeyWrap(KDF(DH-Shared, context), CEK)
                binary_t kw_iv;
                kw_iv.resize(8);
                memset(&kw_iv[0], 0xa6, kw_iv.size());
            } else if (cose_group_t::cose_group_rsassa_pss == group) {
            } else if (cose_group_t::cose_group_rsa_oaep == group) {
            } else if (cose_group_t::cose_group_rsassa_pkcs15 == group) {
            } else if (cose_group_t::cose_group_aesgcm == group) {
                // RFC 8152 10.1. AES GCM
            } else if (cose_group_t::cose_group_hmac == group) {
            } else if (cose_group_t::cose_group_aesccm == group) {
                // RFC 8152 10.2. AES CCM
            } else if (cose_group_t::cose_group_aescbc_mac == group) {
                // RFC 9.2. AES Message Authentication Code (AES-CBC-MAC)
            } else if (cose_group_t::cose_group_chacha20 == group) {
                // RFC 8152 10.3. ChaCha20 and Poly1305
            } else if (cose_group_t::cose_group_iv == group) {
            }

            basic_stream bs;
            dump_memory(authenticated_data, &bs);
            printf("aad\n%s\n%s\n", bs.c_str(), base16_encode(authenticated_data).c_str());
            if (cek.size()) {
                dump_memory(cek, &bs);
                printf("cek\n%s\n%s\n", bs.c_str(), base16_encode(cek).c_str());
            }
            if (context.size()) {
                dump_memory(context, &bs);
                printf("context\n%s\n%s\n", bs.c_str(), base16_encode(context).c_str());
            }
            if (decrypted.size()) {
                dump_memory(decrypted, &bs);
                printf("decrypted\n%s\n%s\n", bs.c_str(), base16_encode(decrypted).c_str());
            }
            if (iv.size()) {
                dump_memory(iv, &bs);
                printf("iv\n%s\n\%s\n", bs.c_str(), base16_encode(iv).c_str());
            }
            if (salt.size()) {
                dump_memory(salt, &bs);
                printf("salt\n%s\n%s\n", bs.c_str(), base16_encode(salt).c_str());
            }
            if (secret.size()) {
                dump_memory(secret, &bs);
                printf("secret\n%s\n%s\n", bs.c_str(), base16_encode(secret).c_str());
            }
        }

        if ((1 == results.size()) && (true == *results.begin())) {
            result = true;
            ret = errorcode_t::success;
        }
    }
    __finally2 { cbor_object_signing_encryption::clear_context(handle); }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
