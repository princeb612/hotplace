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
#include <hotplace/sdk/crypto/basic/openssl_chacha20.hpp>
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
#include <hotplace/sdk/io/types.hpp>

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

cbor_data* cbor_data_kdf_context_item(cose_context_t* handle, cose_parts_t* source, cose_key_t key, cose_param_t shared) {
    return_t ret = errorcode_t::success;
    cbor_object_signing_encryption::composer composer;
    cbor_data* data = nullptr;
    binary_t bin;
    if (source) {
        composer.finditem(key, bin, source->unprotected_map);
    }
    if (0 == bin.size()) {
        bin = handle->binarymap[shared];
    }
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
                composer.finditem(cose_key_t::cose_alg, algid, handle->body.protected_map);
                break;
        }

        int keylen = 0;
        switch (algid) {
            case cose_aes128kw:
            case cose_aes128gcm:
            case cose_aescmac_128_64:
            case cose_aescmac_128_128:
            case cose_aesccm_16_64_128:
            case cose_aesccm_64_64_128:
            case cose_aesccm_16_128_128:
            case cose_aesccm_64_128_128:
            case cose_hkdf_sha256:
            case cose_hkdf_aescmac128:
            case cose_ecdhes_hkdf_256:
            case cose_ecdhss_hkdf_256:
            case cose_hs256_64:
            case cose_hs256:
                keylen = 128;
                break;
            case cose_aes192kw:
            case cose_aes192gcm:
            case cose_hs384:
                keylen = 192;
                break;
            case cose_aes256kw:
            case cose_aes256gcm:
            case cose_aescmac_256_64:
            case cose_aescmac_256_128:
            case cose_aesccm_16_64_256:
            case cose_aesccm_64_64_256:
            case cose_aesccm_16_128_256:
            case cose_aesccm_64_128_256:
            case cose_hkdf_sha512:
            case cose_hkdf_aescmac256:
            case cose_ecdhes_hkdf_512:
            case cose_ecdhss_hkdf_512:
            case cose_hs512:
                keylen = 256;
                break;
            default:
                ret = errorcode_t::not_supported;  // studying
                break;
        }

        if (0 == keylen) {
            throw;  // studying
        }

        root = new cbor_array();
        *root << new cbor_data(algid) << new cbor_array() << new cbor_array() << new cbor_array();
        cbor_array* partyu = (cbor_array*)(*root)[1];
        cbor_array* partyv = (cbor_array*)(*root)[2];
        cbor_array* pub = (cbor_array*)(*root)[3];
        // PartyUInfo
        {
            *partyu << cbor_data_kdf_context_item(handle, source, cose_key_t::cose_partyu_id, cose_param_t::cose_unsent_apu_id)
                    << cbor_data_kdf_context_item(handle, source, cose_key_t::cose_partyu_nonce, cose_param_t::cose_unsent_apu_nonce)
                    << cbor_data_kdf_context_item(handle, source, cose_key_t::cose_partyu_other, cose_param_t::cose_unsent_apu_other);
        }
        // PartyVInfo
        {
            *partyv << cbor_data_kdf_context_item(handle, source, cose_key_t::cose_partyv_id, cose_param_t::cose_unsent_apv_id)
                    << cbor_data_kdf_context_item(handle, source, cose_key_t::cose_partyv_nonce, cose_param_t::cose_unsent_apv_nonce)
                    << cbor_data_kdf_context_item(handle, source, cose_key_t::cose_partyv_other, cose_param_t::cose_unsent_apv_other);
        }
        // SuppPubInfo
        {
            *pub << new cbor_data(keylen) << new cbor_data(source->bin_protected);
            binary_t bin_public = handle->binarymap[cose_param_t::cose_unsent_pub_other];
            if (bin_public.size()) {
                *pub << new cbor_data(bin_public);
            }
        }
        // SuppPrivInfo
        {
            binary_t bin_private = handle->binarymap[cose_param_t::cose_unsent_priv_other];
            if (bin_private.size()) {
                *root << new cbor_data(bin_private);
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

return_t dodecrypt(cose_context_t* handle, crypto_key* key, int tag, binary_t& output) {
    return_t ret = errorcode_t::not_supported;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    cbor_object_signing_encryption::composer composer;
    int enc_alg = 0;
    openssl_crypt crypt;
    // openssl_hash hash;
    crypt_context_t* crypt_handle = nullptr;
    // hash_context_t* hash_handle = nullptr;

    __try2 {
        composer.finditem(cose_key_t::cose_alg, enc_alg, handle->body.protected_map);

        const hint_cose_algorithm_t* enc_hint = advisor->hintof_cose_algorithm((cose_alg_t)enc_alg);

        maphint<cose_param_t, binary_t> hint(handle->binarymap);

        binary_t partial_iv;
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

        EVP_PKEY* pkey = nullptr;
        binary_t cek;
        hint.find(cose_param_t::cose_param_cek, &cek);
        if (0 == cek.size()) {
            if (cbor_tag_t::cose_tag_encrypt == tag) {
                ret = errorcode_t::request;
                __leave2;
            } else if (cbor_tag_t::cose_tag_encrypt0 == tag) {
                std::string kid;
                const char* k = nullptr;

                composer.finditem(cose_key_t::cose_kid, kid, handle->body.protected_map);
                if (kid.size()) {
                    k = kid.c_str();
                }

                if (k) {
                    pkey = key->find(k, enc_hint->kty);
                } else {
                    pkey = key->select(kid, enc_hint->kty);
                }

#if defined DEBUG
                if (nullptr == pkey) {
                    handle->debug_flag |= cose_debug_notfound_key;
                }
#endif

                crypto_kty_t kty;
                key->get_privkey(pkey, kty, cek, true);
            } else {
                ret = errorcode_t::request;
                __leave2;
            }
        }

        binary_t authenticated_data = handle->binarymap[cose_param_t::cose_param_aad];

        binary_t tag;

        // cose_group_aeskw
        // cose_group_direct
        // cose_group_ecdsa
        // cose_group_eddsa
        // cose_group_hkdf_hmac
        // cose_group_hkdf_aescmac
        // cose_group_sha
        // cose_group_ecdhes_hkdf
        // cose_group_ecdhss_hkdf
        // cose_group_ecdhes_aeskw
        // cose_group_ecdhss_aeskw
        // cose_group_rsassa_pss
        // cose_group_rsa_oaep
        // cose_group_rsassa_pkcs15
        // cose_group_aesgcm
        // cose_group_hmac
        // cose_group_aesccm
        // cose_group_aescmac
        // cose_group_chacha20_poly1305
        // cose_group_iv
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

        composer.parse(handle, input);

        // AAD_hex
        binary_t authenticated_data;
        compose_enc_structure(authenticated_data, handle->cbor_tag, handle->body.bin_protected, handle->binarymap[cose_param_t::cose_external]);

        // too many parameters... handle w/ map
        handle->binarymap[cose_param_t::cose_param_aad] = authenticated_data;

        const char* k = nullptr;
        binary_t kwiv;
        binary_t iv;
        int enc_alg = 0;

        kwiv.resize(8);
        memset(&kwiv[0], 0xa6, kwiv.size());

        composer.finditem(cose_key_t::cose_iv, iv, handle->body.unprotected_map);
        composer.finditem(cose_key_t::cose_alg, enc_alg, handle->body.protected_map);

        size_t size_subitems = handle->subitems.size();
        std::list<cose_parts_t>::iterator iter;
        for (iter = handle->subitems.begin(); iter != handle->subitems.end(); iter++) {
            cose_parts_t& item = *iter;

            binary_t ciphertext;
            binary_t context;
            binary_t cek;
            binary_t kek;
            binary_t salt;
            binary_t secret;
            binary_t tag;

            openssl_crypt crypt;
            openssl_hash hash;
            crypt_context_t* crypt_handle = nullptr;
            hash_context_t* hash_handle = nullptr;

            int alg = 0;
            std::string kid;
            return_t check = errorcode_t::success;
            composer.finditem(cose_key_t::cose_alg, alg, item.protected_map);
            if (0 == alg) {
                composer.finditem(cose_key_t::cose_alg, alg, item.unprotected_map);
            }
            composer.finditem(cose_key_t::cose_kid, kid, item.unprotected_map);
            if (kid.size()) {
                k = kid.c_str();
            }

            composer.finditem(cose_key_t::cose_iv, iv, item.unprotected_map);
            composer.finditem(cose_key_t::cose_salt, salt, item.unprotected_map);

            const hint_cose_algorithm_t* alg_hint = advisor->hintof_cose_algorithm((cose_alg_t)alg);
            if (nullptr == alg_hint) {
#if defined DEBUG
                throw errorcode_t::internal_error;
#endif
                continue;
            }

            if (k) {
                pkey = key->find(k, alg_hint->kty);
            } else {
                std::string selected_kid;
                pkey = key->select(selected_kid, alg_hint->kty);
            }
            if (nullptr == pkey) {
#if defined DEBUG
                handle->debug_flag |= cose_debug_notfound_key;
                // throw errorcode_t::internal_error;
#endif
                continue;
            }

            crypto_kty_t kty;
            EVP_PKEY* epk = nullptr;

            switch (alg_hint->kty) {
                case crypto_kty_t::kty_hmac:
                    key->get_privkey(pkey, kty, secret, true);
                    break;
                case crypto_kty_t::kty_ec:
                    if (composer.exist(cose_key_t::cose_static_key_id, item.unprotected_map)) {
                        std::string static_keyid;
                        composer.finditem(cose_key_t::cose_static_key_id, static_keyid, item.unprotected_map);
                        epk = key->find(static_keyid.c_str(), alg_hint->kty);
                    } else {
                        epk = item.epk;
                    }
                    break;
                default:
                    break;
            }

            cose_group_t group = alg_hint->group;

            // reversing "AAD_hex", "CEK_hex", "Context_hex", "KEK_hex" from https://github.com/cose-wg/Examples

#if defined DEBUG
            printf("alg %i group %i\n", alg, group);
#endif

            if (cose_group_t::cose_group_aeskw == group) {
                kek = secret;
                crypt.open(&crypt_handle, alg_hint->param.algname, kek, kwiv);
                crypt.decrypt(crypt_handle, item.bin_data, cek);
                crypt.close(crypt_handle);
            } else if (cose_group_t::cose_group_direct == group) {
                // RFC 8152 12.1. Direct Encryption
                cek = secret;
            } else if (cose_group_t::cose_group_ecdsa == group) {
                // RFC 8152 8.1. ECDSA
            } else if (cose_group_t::cose_group_eddsa == group) {
                // RFC 8152 8.2. Edwards-Curve Digital Signature Algorithms (EdDSAs)
            } else if (cose_group_t::cose_group_hkdf_hmac == group) {
                // RFC 8152 12.1.2.  Direct Key with KDF
                compose_kdf_context(handle, &item, context);

                // using context structure to transform the shared secret into the CEK
                // either the 'salt' parameter of HKDF ot the 'PartyU nonce' parameter of the context structure MUST be present.
                kdf_hkdf(cek, alg_hint->kdf.algname, alg_hint->kdf.dlen, secret, salt, context);
                // CEK solved
            } else if (cose_group_t::cose_group_hkdf_aescmac == group) {
                compose_kdf_context(handle, &item, context);

                // RFC 8152 11.1.  HMAC-Based Extract-and-Expand Key Derivation Function (HKDF)
                // RFC 8152 Table 12: HKDF Algorithms
                //      HKDF AES-MAC-128, AES-CBC-MAC-128, HKDF using AES-MAC as the PRF w/ 128-bit key
                //      HKDF AES-MAC-256, AES-CBC-MAC-256, HKDF using AES-MAC as the PRF w/ 256-bit key

                // HKDF is defined to use HMAC as the underlying PRF.  However, it is
                // possible to use other functions in the same construct to provide a
                // different KDF that is more appropriate in the constrained world.
                // Specifically, one can use AES-CBC-MAC as the PRF for the expand step,
                // but not for the extract step.  When using a good random shared secret
                // of the correct length, the extract step can be skipped.  For the AES
                // algorithm versions, the extract step is always skipped.

                // TEST FAILED
                // try ckdf_expand - CEK_hex mismatch

#if defined DEBUG
                handle->debug_flag |= cose_debug_hkdf_aescmac;
#endif
            } else if (cose_group_t::cose_group_sha == group) {
            } else if (cose_group_t::cose_group_ecdhes_hkdf == group) {
                // RFC 8152 12.4.1. ECDH
                // RFC 8152 11.1.  HMAC-Based Extract-and-Expand Key Derivation Function (HKDF)
                dh_key_agreement(pkey, epk, secret);

                compose_kdf_context(handle, &item, context);

                salt.resize(alg_hint->kdf.dlen);
                kdf_hkdf(cek, alg_hint->kdf.algname, alg_hint->kdf.dlen, secret, salt, context);
                // CEK solved
            } else if (cose_group_t::cose_group_ecdhss_hkdf == group) {
                // RFC 8152 12.4.1. ECDH
                // RFC 8152 11.1.  HMAC-Based Extract-and-Expand Key Derivation Function (HKDF)
                dh_key_agreement(pkey, epk, secret);

                compose_kdf_context(handle, &item, context);

                salt.resize(alg_hint->kdf.dlen);
                kdf_hkdf(cek, alg_hint->kdf.algname, alg_hint->kdf.dlen, secret, salt, context);
                // CEK solved
            } else if (cose_group_t::cose_group_ecdhes_aeskw == group || cose_group_t::cose_group_ecdhss_aeskw == group) {
                // RFC 8152 12.5.1. ECDH
                // RFC 8152 12.2.1. AES Key Wrap
                dh_key_agreement(pkey, epk, secret);

                compose_kdf_context(handle, &item, context);

                salt.resize(alg_hint->kdf.dlen);
                kdf_hkdf(kek, alg_hint->kdf.algname, alg_hint->kdf.dlen, secret, salt, context);

                // 12.5.  Key Agreement with Key Wrap
                crypt.open(&crypt_handle, alg_hint->param.algname, kek, kwiv);
                crypt.decrypt(crypt_handle, item.bin_data, cek);
                crypt.close(crypt_handle);
            } else if (cose_group_t::cose_group_rsassa_pss == group) {
            } else if (cose_group_t::cose_group_rsa_oaep == group) {
                crypt_enc_t mode;
                switch (alg) {
                    case cose_alg_t::cose_rsaes_oaep_sha1:
                        mode = crypt_enc_t::rsa_oaep;
                        break;
                    case cose_alg_t::cose_rsaes_oaep_sha256:
                        mode = crypt_enc_t::rsa_oaep256;
                        break;
                    case cose_alg_t::cose_rsaes_oaep_sha512:
                        mode = crypt_enc_t::rsa_oaep512;
                        break;
                    default:
                        break;
                }
                crypt.decrypt(pkey, item.bin_data, cek, mode);
            } else if (cose_group_t::cose_group_rsassa_pkcs15 == group) {
            } else if (cose_group_t::cose_group_aesgcm == group) {
                // RFC 8152 10.1. AES GCM
            } else if (cose_group_t::cose_group_hmac == group) {
            } else if (cose_group_t::cose_group_aesccm == group) {
                // RFC 8152 10.2. AES CCM
            } else if (cose_group_t::cose_group_aescmac == group) {
                // RFC 9.2. AES Message Authentication Code (AES-CBC-MAC)
            } else if (cose_group_t::cose_group_chacha20_poly1305 == group) {
                // RFC 8152 10.3. ChaCha20 and Poly1305
#if defined DEBUG
                handle->debug_flag |= cose_debug_chacha20_poly1305;
#endif
            } else if (cose_group_t::cose_group_iv == group) {
            }

            basic_stream bs;
#if defined DEBUG
            dump_memory(authenticated_data, &bs);
            printf("AAD\n%s\n%s\n", bs.c_str(), base16_encode(authenticated_data).c_str());
            dump_memory(context, &bs);
            printf("Context\n%s\n%s\n", bs.c_str(), base16_encode(context).c_str());
            if (secret.size()) {
                dump_memory(secret, &bs);
                printf("secret\n%s\n%s\n", bs.c_str(), base16_encode(secret).c_str());
            }
            if (iv.size()) {
                dump_memory(iv, &bs);
                printf("IV\n%s\n%s\n", bs.c_str(), base16_encode(iv).c_str());
            }
            if (kek.size()) {
                dump_memory(kek, &bs);
                printf("KEK\n%s\n%s\n", bs.c_str(), base16_encode(kek).c_str());
            }
#endif

            if (cek.size()) {
#if defined DEBUG
                dump_memory(cek, &bs);
                printf("CEK\n%s\n%s\n", bs.c_str(), base16_encode(cek).c_str());
#endif

                // too many parameters... handle w/ map
                handle->binarymap[cose_param_t::cose_param_cek] = cek;
                check = dodecrypt(handle, key, cbor_tag_t::cose_tag_encrypt, output);

                results.insert((errorcode_t::success == check) ? true : false);
            }
        }
        if (0 == handle->subitems.size()) {
            check = dodecrypt(handle, key, cbor_tag_t::cose_tag_encrypt0, output);

            results.insert((errorcode_t::success == check) ? true : false);
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
