/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 7516 JSON Web Encryption (JWE)
 *  RFC 7518 JSON Web Algorithms (JWA)
 *
 * Revision History
 * Date         Name                Description
 */

#include <iostream>
#include <sdk/base.hpp>
#include <sdk/base/basic/base64.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/crypto_keychain.hpp>
#include <sdk/crypto/basic/evp_key.hpp>
#include <sdk/crypto/basic/openssl_crypt.hpp>
#include <sdk/crypto/basic/openssl_ecdh.hpp>
#include <sdk/crypto/basic/openssl_hash.hpp>
#include <sdk/crypto/basic/openssl_kdf.hpp>
#include <sdk/crypto/basic/openssl_prng.hpp>
#include <sdk/crypto/jose/json_object_encryption.hpp>
#include <sdk/crypto/jose/json_object_signing.hpp>
#include <sdk/crypto/jose/json_object_signing_encryption.hpp>
#include <sdk/crypto/jose/json_web_key.hpp>
#include <sdk/io/basic/json.hpp>
#include <sdk/io/basic/zlib.hpp>
#include <sdk/io/string/string.hpp>
#include <sdk/io/system/types.hpp>

namespace hotplace {
using namespace io;
namespace crypto {

json_object_encryption::json_object_encryption() {
    // do nothing
}

json_object_encryption::~json_object_encryption() {
    // do nothing
}

return_t json_object_encryption::encrypt(jose_context_t* handle, jwe_t enc, jwa_t alg, binary_t const& input, std::string& output, jose_serialization_t type) {
    return_t ret = errorcode_t::success;
    json_object_encryption::composer composer;

    __try2 {
        json_object_signing_encryption::clear_context(handle);
        output.clear();

        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        std::list<jwa_t> algs;
        algs.push_back(alg);
        composer.compose_encryption_dorandom(handle, enc, algs);

        binary_t encrypted;
        if (jose_flag_t::jose_deflate & handle->flags) {
            binary_t deflated;
            zlib_deflate(zlib_windowbits_t::windowbits_deflate, input, deflated);

            ret = doencrypt(handle, enc, alg, deflated, encrypted);
        } else {
            ret = doencrypt(handle, enc, alg, input, encrypted);
        }
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = composer.compose_encryption(handle, output, type);
    }
    __finally2 { json_object_signing_encryption::clear_context(handle); }
    return ret;
}

return_t json_object_encryption::encrypt(jose_context_t* handle, jwe_t enc, std::list<jwa_t> algs, binary_t const& input, std::string& output,
                                         jose_serialization_t type) {
    return_t ret = errorcode_t::success;
    json_object_encryption::composer composer;

    __try2 {
        json_object_signing_encryption::clear_context(handle);
        output.clear();

        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        for (std::list<jwa_t>::iterator it = algs.begin(); it != algs.end();) {
            if (jwa_t::jwa_dir == *it || jwa_t::jwa_ecdh_es == *it) {
                // support "dir" for decryption only ...
                it = algs.erase(it);
            } else {
                it++;
            }
        }

        binary_t encrypted;

        composer.compose_encryption_dorandom(handle, enc, algs);

        binary_t deflated;
        if (jose_flag_t::jose_deflate & handle->flags) {
            zlib_deflate(zlib_windowbits_t::windowbits_deflate, input, deflated);
        }

        for (std::list<jwa_t>::iterator iter = algs.begin(); iter != algs.end(); iter++) {
            jwa_t alg = *iter;

            return_t check = errorcode_t::success;

            if (jose_flag_t::jose_deflate & handle->flags) {
                check = doencrypt(handle, enc, alg, deflated, encrypted);
            } else {
                check = doencrypt(handle, enc, alg, input, encrypted);
            }

            switch (check) {
                case errorcode_t::success:
                case errorcode_t::not_supported:
                    break;
                default:
                    ret = check;
            }
            if (errorcode_t::success != ret) {
                break;
            }
        }

        composer.compose_encryption(handle, output, type);
    }
    __finally2 { json_object_signing_encryption::clear_context(handle); }
    return ret;
}

return_t json_object_encryption::decrypt(jose_context_t* handle, std::string const& input, binary_t& output, bool& result) {
    return_t ret = errorcode_t::success;
    json_object_encryption::composer composer;

    __try2 {
        json_object_signing_encryption::clear_context(handle);
        output.clear();
        result = false;

        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        composer.parse_decryption(handle, input.c_str());

        return_t ret_test = errorcode_t::success;
        std::list<bool> results;
        for (jose_encryptions_map_t::iterator eit = handle->encryptions.begin(); eit != handle->encryptions.end(); eit++) {
            jwe_t enc = eit->first;
            jose_encryption_t& item = eit->second;

            binary_t zip;
            maphint<crypt_item_t, binary_t> hint(item.datamap);
            hint.find(crypt_item_t::item_zip, &zip);

            for (jose_recipients_t::iterator rit = item.recipients.begin(); rit != item.recipients.end(); rit++) {
                jwa_t alg = rit->first;

                bool run = true;

                if (run) {
                    jose_recipient_t& recipient = rit->second;

                    std::string kid;

                    if (false == recipient.kid.empty()) {
                        kid = recipient.kid;
                    } else if (false == item.kid.empty()) {
                        kid = item.kid;
                    }

                    if (kid.empty()) {
                        ret_test = dodecrypt(handle, enc, alg, item.datamap[crypt_item_t::item_ciphertext], output);
                    } else {
                        ret_test = dodecrypt(handle, enc, alg, kid.c_str(), item.datamap[crypt_item_t::item_ciphertext], output);
                    }
                    if ((errorcode_t::success == ret_test) && zip.size() && (0 == memcmp(&zip[0], "DEF", 3))) {
                        binary_t inflated;
                        zlib_inflate(zlib_windowbits_t::windowbits_deflate, output, inflated);
                        output = inflated;
                    }

                    results.push_back((bool)(errorcode_t::success == ret_test));
                }
            }
        }

        if (results.empty()) {
            ret = errorcode_t::not_supported;
        } else {
            results.unique();
            if (1 == results.size() && true == results.front()) {
                //
            } else {
                ret = errorcode_t::error_cipher;
            }
        }
    }
    __finally2 { json_object_signing_encryption::clear_context(handle); }
    return ret;
}

return_t json_object_encryption::doencrypt(jose_context_t* handle, jwe_t enc, jwa_t alg, binary_t const& input, binary_t& output) {
    return_t ret = errorcode_t::success;
    json_object_encryption::composer composer;
    openssl_crypt crypt;
    openssl_hash hash;
    openssl_kdf kdf;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        jose_encryptions_map_t::iterator iter = handle->encryptions.find(enc);
        if (handle->encryptions.end() == iter) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        const hint_jose_encryption_t* alg_hint = advisor->hintof_jose_algorithm(alg);   // key management
        const hint_jose_encryption_t* enc_hint = advisor->hintof_jose_encryption(enc);  // content encryption

        jose_encryption_t& item = iter->second;
        binary_t cek = item.datamap[crypt_item_t::item_cek];                                      // in, enc
        binary_t iv = item.datamap[crypt_item_t::item_iv];                                        // in, enc
        binary_t& aad = item.datamap[crypt_item_t::item_aad];                                     // in, enc
        binary_t& encrypted_key = item.recipients[alg].datamap[crypt_item_t::item_encryptedkey];  // out, alg
        binary_t& tag = item.datamap[crypt_item_t::item_tag];                                     // out, enc
        binary_t& ciphertext = item.datamap[crypt_item_t::item_ciphertext];                       // out, enc

        // alg part - encrypted_key from cek
        {
            const char* alg_name = alg_hint->alg_name;
            crypt_enc_t crypt_mode = (crypt_enc_t)alg_hint->mode;
            crypt_algorithm_t alg_crypt_alg = (crypt_algorithm_t)alg_hint->crypt_alg;
            crypt_mode_t alg_crypt_mode = (crypt_mode_t)alg_hint->crypt_mode;
            int alg_keysize = alg_hint->keysize;
            hash_algorithm_t alg_hash_alg = (hash_algorithm_t)alg_hint->hash_alg;

            binary_t oct;
            /* RFC3394 Advanced Encryption Standard (AES) Key Wrap Algorithm
             * 2.2.3.1 Default Initial Value
             * iv 0xa6 ...
             */
            binary_t kw_iv;
            kw_iv.resize(8);
            memset(&kw_iv[0], 0xa6, kw_iv.size());

            std::string kid;
            const EVP_PKEY* pkey = handle->key->select(kid, alg, crypto_use_t::use_enc);
            if (nullptr == pkey) {
                ret = errorcode_t::not_found;
                __leave2;
            }

            ret = check_constraints(alg, pkey);
            if (errorcode_t::success != ret) {
                __leave2;
            }

            if (crypto_kty_t::kty_oct == alg_hint->kty) {
                /* EVP_KEY_HMAC key data and length */
                crypto_kty_t kty;
                crypto_key::get_privkey(pkey, kty, oct, true);
            }

            uint32 alg_group = alg_hint->group;
            if (jwa_group_t::jwa_group_rsa == alg_group) {
                /*
                 * RSA1_5, RSA-OAEP, RSA-OAEP-256
                 * RFC7518 4.2.  Key Encryption with RSAES-PKCS1-v1_5
                 * A key of size 2048 bits or larger MUST be used with this algorithm.
                 * RFC7518 4.3.  Key Encryption with RSAES OAEP
                 * A key of size 2048 bits or larger MUST be used with this algorithm.
                 * RFC7520 5.1. Key Encryption Using RSA v1.5 and AES-HMAC-SHA2
                 * RFC7520 5.2. Key Encryption Using RSA-OAEP with AES-GCM
                 */
                ret = crypt.encrypt(pkey, cek, encrypted_key, crypt_mode);
            } else if (jwa_group_t::jwa_group_aeskw == alg_group) {
                /*
                 * A128KW, A192KW, A256KW
                 * RFC7518 4.4. Key Wrapping with AES Key Wrap
                 * RFC7520 5.8. Key Wrap Using AES-KeyWrap with AES-GCM
                 */
                // crypt_context_t* handle_kw = nullptr;
                // crypt.open(&handle_kw, alg_crypt_alg, alg_crypt_mode, &oct[0], oct.size(), &kw_iv[0], kw_iv.size());
                // ret = crypt.encrypt(handle_kw, &cek[0], cek.size(), encrypted_key);
                // crypt.close(handle_kw);
                ret = crypt.encrypt(alg_crypt_alg, alg_crypt_mode, oct, kw_iv, cek, encrypted_key);
            } else if (jwa_group_t::jwa_group_dir == alg_group) {
                /*
                 * dir
                 * RFC7518 4.5. Direct Encryption with a Shared Symmetric Key
                 * RFC7520 5.6. Direct Encryption Using AES-GCM
                 */

                /* read cek from HMAC key and then make it the only one cek */
                cek = oct;
            } else if (jwa_group_t::jwa_group_ecdh == alg_group) {
                /*
                 * ECDH-ES
                 * RFC7518 4.6. Key Agreement with Elliptic Curve Diffie-Hellman Ephemeral Static (ECDH-ES)
                 * 1.  directly as the Content Encryption Key (CEK) for the "enc"
                 *     algorithm, in the Direct Key Agreement mode, or
                 * RFC7520 5.5. Key Agreement Using ECDH-ES with AES-CBC-HMAC-SHA2
                 */
                const EVP_PKEY* epk = item.recipients[alg].epk;
                int keylen = enc_hint->keysize;
                uint32 enc_group = enc_hint->group;
                if (jwe_group_t::jwe_group_aescbc_hs == enc_group) {
                    keylen *= 2;
                }

                ret = ecdh_es(epk, pkey, enc_hint->alg_name, "", "", keylen, cek);
                encrypted_key = cek;
            } else if (jwa_group_t::jwa_group_ecdh_aeskw == alg_group) {
                /*
                 * ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW
                 * RFC7518 4.6. Key Agreement with Elliptic Curve Diffie-Hellman Ephemeral Static (ECDH-ES)
                 * 2.  as a symmetric key used to wrap the CEK with the "A128KW",
                 *     "A192KW", or "A256KW" algorithms, in the Key Agreement with Key
                 *     Wrapping mode.
                 * RFC7520 5.4. Key Agreement with Key Wrapping Using ECDH-ES and AES-KeyWrap with AES-GCM
                 */
                binary_t derived_key;
                const EVP_PKEY* epk = item.recipients[alg].epk;
                int keylen = alg_hint->keysize;
                uint32 enc_group = enc_hint->group;
                if (jwe_group_t::jwe_group_aescbc_hs == enc_group) {
                    // keylen *= 2;
                }
                ret = ecdh_es(epk, pkey, alg_hint->alg_name, "", "", keylen, derived_key);

                // crypt_context_t* handle_kw = nullptr;
                // crypt.open(&handle_kw, alg_crypt_alg, alg_crypt_mode, &derived_key[0], derived_key.size(), &kw_iv[0], kw_iv.size());
                // ret = crypt.encrypt(handle_kw, &cek[0], cek.size(), encrypted_key);
                // crypt.close(handle_kw);
                ret = crypt.encrypt(alg_crypt_alg, alg_crypt_mode, derived_key, kw_iv, cek, encrypted_key);
            } else if (jwa_group_t::jwa_group_aesgcmkw == alg_group) {
                /*
                 * A128GCMKW, A192GCMKW, A256GCMKW
                 * RFC7518 4.7. Key Encryption with AES GCM
                 * RFC7520 5.7. Key Wrap Using AES-GCM KeyWrap with AES-CBC-HMAC-SHA2
                 */
                binary_t iv1 = item.recipients[alg].datamap[crypt_item_t::item_iv];
                binary_t aad1;                                                          // empty
                binary_t& tag1 = item.recipients[alg].datamap[crypt_item_t::item_tag];  // compute authencation tag here

                // crypt_context_t* handle_crypt = nullptr;
                // crypt.open(&handle_crypt, alg_crypt_alg, alg_crypt_mode, &oct[0], oct.size(), &iv1[0], iv1.size());
                // ret = crypt.encrypt2(handle_crypt, &cek[0], cek.size(), encrypted_key, &aad1, &tag1);
                // crypt.close(handle_crypt);
                ret = crypt.encrypt(alg_crypt_alg, alg_crypt_mode, oct, iv1, cek, encrypted_key, aad1, tag1);

                /*
                 * tag updated
                 * json serialization - jwe.output using recipient
                 * json flattened, compact - computed tag information must be written in protected_header
                 */
                if (1 == handle->encryptions.size()) {
                    /* compact, flattened */
                    std::string header;
                    composer.compose_encryption_aead_header(item.header, tag1, aad, header);
                    if (header.size()) {
                        item.header = header;
                    }
                }
            } else if (jwa_group_t::jwa_group_pbes_hs_aeskw == alg_group) {
                /*
                 * RFC7518 4.8. Key Encryption with PBES2
                 * PBES2-HS256+A128KW, PBES2-HS384+A192KW, PBES2-HS512+A256KW
                 * RFC7520 5.3. Key Wrap Using PBES2-AES-KeyWrap with AES-CBC-HMAC-SHA2
                 */
                binary_t p2s = item.recipients[alg].datamap[crypt_item_t::item_p2s];
                uint32 p2c = item.recipients[alg].p2c;

                binary_t salt;

                /* salt
                 * salt = UTF8(alg) + 0 + BASE64URL_DECODE(p2s)
                 */
                salt.insert(salt.end(), (byte_t*)alg_name, (byte_t*)alg_name + strlen(alg_name));
                salt.insert(salt.end(), 0);
                salt.insert(salt.end(), p2s.begin(), p2s.end());

                /* key derivation
                 * derived_key = PKCS5_PBKDF2_HMAC(passphrase, salt, iteration_count = p2c, hash)
                 */
                // oct.resize(0);
                binary_t pbkdf2_derived_key;
                // pbkdf2_derived_key.resize (alg_keysize);
                // const EVP_MD* alg_evp_md = (const EVP_MD*) advisor->find_evp_md (alg_hash_alg);
                // PKCS5_PBKDF2_HMAC ((char *) &oct[0], oct.size (), &salt[0], salt.size (), p2c, alg_evp_md,
                //                    pbkdf2_derived_key.size (), &pbkdf2_derived_key[0]);
                kdf.pbkdf2(pbkdf2_derived_key, alg_hash_alg, alg_keysize, convert(oct), salt, p2c);

                // crypt_context_t* crypt_handle = nullptr;
                // crypt.open(&crypt_handle, alg_crypt_alg, alg_crypt_mode, &pbkdf2_derived_key[0], pbkdf2_derived_key.size(), &kw_iv[0],
                //            kw_iv.size());
                // ret = crypt.encrypt(crypt_handle, &cek[0], cek.size(), encrypted_key);
                // crypt.close(crypt_handle);
                ret = crypt.encrypt(alg_crypt_alg, alg_crypt_mode, pbkdf2_derived_key, kw_iv, cek, encrypted_key);
            }
        }

        if (errorcode_t::success != ret) {
            __leave2;
        }

        // enc part - ciphertext using cek, iv
        {
            crypt_algorithm_t enc_crypt_alg = (crypt_algorithm_t)enc_hint->crypt_alg;
            crypt_mode_t enc_crypt_mode = (crypt_mode_t)enc_hint->crypt_mode;
            hash_algorithm_t enc_hash_alg = (hash_algorithm_t)enc_hint->hash_alg;

            uint32 enc_group = enc_hint->group;
            if (jwe_group_t::jwe_group_aescbc_hs == enc_group) {
                // // RFC 7516 Appendix B.  Example AES_128_CBC_HMAC_SHA_256 Computation
                openssl_aead aead;
                ret = aead.aes_cbc_hmac_sha2_encrypt(enc_crypt_alg, enc_crypt_mode, enc_hash_alg, cek, iv, aad, input, ciphertext, tag);
            } else if (jwe_group_t::jwe_group_aesgcm == enc_group) {
                // crypt_context_t* handle_crypt = nullptr;
                // crypt.open(&handle_crypt, enc_crypt_alg, enc_crypt_mode, &cek[0], cek.size(), &iv[0], iv.size());
                // /* Content Encryption */
                // ret = crypt.encrypt2(handle_crypt, &input[0], input.size(), ciphertext, &aad, &tag);
                // crypt.close(handle_crypt);
                ret = crypt.encrypt(enc_crypt_alg, enc_crypt_mode, cek, iv, input, ciphertext, aad, tag);
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t json_object_encryption::dodecrypt(jose_context_t* handle, jwe_t enc, jwa_t alg, binary_t const& input, binary_t& output) {
    return dodecrypt(handle, enc, alg, nullptr, input, output);
}

return_t json_object_encryption::dodecrypt(jose_context_t* handle, jwe_t enc, jwa_t alg, const char* kid, binary_t const& input, binary_t& output) {
    return_t ret = errorcode_t::success;
    openssl_crypt crypt;
    openssl_hash hash;
    openssl_kdf kdf;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        jose_encryptions_map_t::iterator iter = handle->encryptions.find(enc);
        if (handle->encryptions.end() == iter) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        const hint_jose_encryption_t* alg_hint = advisor->hintof_jose_algorithm(alg);   // key management
        const hint_jose_encryption_t* enc_hint = advisor->hintof_jose_encryption(enc);  // content encryption

        if (nullptr == alg_hint || nullptr == enc_hint) {
            ret = errorcode_t::request;
            __leave2;
        }

        jose_encryption_t& item = iter->second;
        binary_t cek;                                                                            // local, enc, from encrypted_key
        binary_t iv = item.datamap[crypt_item_t::item_iv];                                       // in, enc
        binary_t aad = item.datamap[crypt_item_t::item_aad];                                     // in, enc
        binary_t encrypted_key = item.recipients[alg].datamap[crypt_item_t::item_encryptedkey];  // in, alg
        binary_t tag = item.datamap[crypt_item_t::item_tag];                                     // in, enc
        binary_t ciphertext = item.datamap[crypt_item_t::item_ciphertext];                       // in, enc
        binary_t apu = item.recipients[alg].datamap[crypt_item_t::item_apu];
        binary_t apv = item.recipients[alg].datamap[crypt_item_t::item_apv];

        // alg part - encrypted_key from cek
        {
            const char* alg_name = alg_hint->alg_name;
            crypt_enc_t crypt_mode = (crypt_enc_t)alg_hint->mode;
            crypt_algorithm_t alg_crypt_alg = (crypt_algorithm_t)alg_hint->crypt_alg;
            crypt_mode_t alg_crypt_mode = (crypt_mode_t)alg_hint->crypt_mode;
            int alg_keysize = alg_hint->keysize;
            hash_algorithm_t alg_hash_alg = (hash_algorithm_t)alg_hint->hash_alg;

            binary_t oct;
            /* RFC3394 Advanced Encryption Standard (AES) Key Wrap Algorithm
             * 2.2.3.1 Default Initial Value
             * iv 0xa6 ...
             */
            binary_t kw_iv;
            kw_iv.resize(8);
            memset(&kw_iv[0], 0xa6, kw_iv.size());

            const EVP_PKEY* pkey = nullptr;
            if (kid) {
                pkey = handle->key->find(kid, alg, crypto_use_t::use_enc);
            } else {
                std::string kid_selected;
                pkey = handle->key->select(kid_selected, alg, crypto_use_t::use_enc);
            }

            if (nullptr == pkey) {
                ret = errorcode_t::not_found;
                __leave2;
            }
            ret = check_constraints(alg, pkey);
            if (errorcode_t::success != ret) {
                __leave2;
            }

            if (crypto_kty_t::kty_oct == alg_hint->kty) {
                /* EVP_KEY_HMAC key data and length */
                // size_t key_length = 0;
                // EVP_PKEY_get_raw_private_key(pkey, nullptr, &key_length);
                // oct.resize(key_length);
                // EVP_PKEY_get_raw_private_key(pkey, &oct[0], &key_length);
                crypto_kty_t kty;
                crypto_key::get_privkey(pkey, kty, oct, true);
            }

            uint32 alg_group = alg_hint->group;
            if (jwa_group_t::jwa_group_rsa == alg_group) {
                /*
                 * RSA1_5, RSA-OAEP, RSA-OAEP-256
                 * RFC7518 4.2.  Key Encryption with RSAES-PKCS1-v1_5
                 * A key of size 2048 bits or larger MUST be used with this algorithm.
                 * RFC7518 4.3.  Key Encryption with RSAES OAEP
                 * A key of size 2048 bits or larger MUST be used with this algorithm.
                 * RFC7520 5.1. Key Encryption Using RSA v1.5 and AES-HMAC-SHA2
                 * RFC7520 5.2. Key Encryption Using RSA-OAEP with AES-GCM
                 */
                ret = crypt.decrypt(pkey, encrypted_key, cek, crypt_mode);
            } else if (jwa_group_t::jwa_group_aeskw == alg_group) {
                /*
                 * A128KW, A192KW, A256KW
                 * RFC7518 4.4. Key Wrapping with AES Key Wrap
                 * RFC7520 5.8. Key Wrap Using AES-KeyWrap with AES-GCM
                 */
                // crypt_context_t* handle_kw = nullptr;
                // crypt.open(&handle_kw, alg_crypt_alg, alg_crypt_mode, &oct[0], oct.size(), &kw_iv[0], kw_iv.size());
                // ret = crypt.decrypt(handle_kw, &encrypted_key[0], encrypted_key.size(), cek);
                // crypt.close(handle_kw);
                ret = crypt.decrypt(alg_crypt_alg, alg_crypt_mode, oct, kw_iv, encrypted_key, cek);
            } else if (jwa_group_t::jwa_group_dir == alg_group) {
                /*
                 * dir
                 * RFC7518 4.5. Direct Encryption with a Shared Symmetric Key
                 * RFC7520 5.6. Direct Encryption Using AES-GCM
                 */
                cek = oct;
            } else if (jwa_group_t::jwa_group_ecdh == alg_group) {
                /*
                 * ECDH-ES
                 * RFC7518 4.6. Key Agreement with Elliptic Curve Diffie-Hellman Ephemeral Static (ECDH-ES)
                 * 1.  directly as the Content Encryption Key (CEK) for the "enc"
                 *     algorithm, in the Direct Key Agreement mode, or
                 * RFC7520 5.5. Key Agreement Using ECDH-ES with AES-CBC-HMAC-SHA2
                 */
                const EVP_PKEY* epk = item.recipients[alg].epk;
                int keylen = enc_hint->keysize;
                uint32 enc_group = enc_hint->group;
                if (jwe_group_t::jwe_group_aescbc_hs == enc_group) {
                    keylen *= 2;
                }

                ret = ecdh_es(pkey, epk, enc_hint->alg_name, "", "", keylen, cek);
            } else if (jwa_group_t::jwa_group_ecdh_aeskw == alg_group) {
                /*
                 * ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW
                 * RFC7518 4.6. Key Agreement with Elliptic Curve Diffie-Hellman Ephemeral Static (ECDH-ES)
                 * 2.  as a symmetric key used to wrap the CEK with the "A128KW",
                 *     "A192KW", or "A256KW" algorithms, in the Key Agreement with Key
                 *     Wrapping mode.
                 * RFC7520 5.4. Key Agreement with Key Wrapping Using ECDH-ES and AES-KeyWrap with AES-GCM
                 */
                binary_t derived_key;
                const EVP_PKEY* epk = item.recipients[alg].epk;
                int keylen = alg_hint->keysize;
                uint32 enc_group = enc_hint->group;
                if (jwe_group_t::jwe_group_aescbc_hs == enc_group) {
                    // keylen *= 2;
                }
                ret = ecdh_es(pkey, epk, alg_hint->alg_name, "", "", keylen, derived_key);

                // crypt_context_t* handle_kw = nullptr;
                // crypt.open(&handle_kw, alg_crypt_alg, alg_crypt_mode, &derived_key[0], derived_key.size(), &kw_iv[0], kw_iv.size());
                // ret = crypt.decrypt(handle_kw, &encrypted_key[0], encrypted_key.size(), cek);
                // crypt.close(handle_kw);
                ret = crypt.decrypt(alg_crypt_alg, alg_crypt_mode, derived_key, kw_iv, encrypted_key, cek);
            } else if (jwa_group_t::jwa_group_aesgcmkw == alg_group) {
                /*
                 * A128GCMKW, A192GCMKW, A256GCMKW
                 * RFC7518 4.7. Key Encryption with AES GCM
                 * RFC7520 5.7. Key Wrap Using AES-GCM KeyWrap with AES-CBC-HMAC-SHA2
                 */
                binary_t iv1 = item.recipients[alg].datamap[crypt_item_t::item_iv];
                binary_t aad1;  // empty
                binary_t tag1 = item.recipients[alg].datamap[crypt_item_t::item_tag];

                /* cek, aad(null), tag = AESGCM (HMAC.key, iv).decrypt (encryted_key) */
                // crypt_context_t* handle_crypt = nullptr;
                // crypt.open(&handle_crypt, alg_crypt_alg, alg_crypt_mode, &oct[0], oct.size(), &iv1[0], iv1.size());
                // ret = crypt.decrypt2(handle_crypt, &encrypted_key[0], encrypted_key.size(), cek, &aad1, &tag1);
                // crypt.close(handle_crypt);
                ret = crypt.decrypt(alg_crypt_alg, alg_crypt_mode, oct, iv1, encrypted_key, cek, aad1, tag1);
            } else if (jwa_group_t::jwa_group_pbes_hs_aeskw == alg_group) {
                /*
                 * RFC7518 4.8. Key Encryption with PBES2
                 * PBES2-HS256+A128KW, PBES2-HS384+A192KW, PBES2-HS512+A256KW
                 * RFC7520 5.3. Key Wrap Using PBES2-AES-KeyWrap with AES-CBC-HMAC-SHA2
                 */
                binary_t p2s = item.recipients[alg].datamap[crypt_item_t::item_p2s];
                uint32 p2c = item.recipients[alg].p2c;

                binary_t salt;
                /* salt
                 * salt = UTF8(alg) + 0 + BASE64URL_DECODE(p2s)
                 */
                salt.insert(salt.end(), (byte_t*)alg_name, (byte_t*)alg_name + strlen(alg_name));
                salt.insert(salt.end(), 0);
                salt.insert(salt.end(), p2s.begin(), p2s.end());

                /* key derivation
                 * derived_key = PKCS5_PBKDF2_HMAC(passphrase, salt, iteration_count = p2c, hash)
                 */
                binary_t pbkdf2_derived_key;
                // pbkdf2_derived_key.resize (alg_keysize);
                // const EVP_MD* alg_evp_md = (const EVP_MD*) advisor->find_evp_md (alg_hash_alg);
                // PKCS5_PBKDF2_HMAC ((char *) &oct[0], oct.size (), &salt[0], salt.size (), p2c, alg_evp_md,
                //                    pbkdf2_derived_key.size (), &pbkdf2_derived_key[0]);
                kdf.pbkdf2(pbkdf2_derived_key, alg_hash_alg, alg_keysize, convert(oct), salt, p2c);

                // crypt_context_t* crypt_handle = nullptr;
                // crypt.open(&crypt_handle, alg_crypt_alg, alg_crypt_mode, &pbkdf2_derived_key[0], pbkdf2_derived_key.size(), &kw_iv[0], kw_iv.size());
                // ret = crypt.decrypt(crypt_handle, &encrypted_key[0], encrypted_key.size(), cek);
                // crypt.close(crypt_handle);
                ret = crypt.decrypt(alg_crypt_alg, alg_crypt_mode, pbkdf2_derived_key, kw_iv, encrypted_key, cek);
            }
        }

        if (errorcode_t::success != ret) {
            __leave2;
        }

        // enc part - ciphertext using cek, iv
        {
            crypt_algorithm_t enc_crypt_alg = (crypt_algorithm_t)enc_hint->crypt_alg;
            crypt_mode_t enc_crypt_mode = (crypt_mode_t)enc_hint->crypt_mode;
            hash_algorithm_t enc_hash_alg = (hash_algorithm_t)enc_hint->hash_alg;

            uint32 enc_group = enc_hint->group;
            if (jwe_group_t::jwe_group_aescbc_hs == enc_group) {
                // RFC 7516 Appendix B.  Example AES_128_CBC_HMAC_SHA_256 Computation
                openssl_aead aead;
                ret = aead.aes_cbc_hmac_sha2_decrypt(enc_crypt_alg, enc_crypt_mode, enc_hash_alg, cek, iv, aad, ciphertext, output, tag);
            } else if (jwe_group_t::jwe_group_aesgcm == enc_group) {
                // crypt_context_t* handle_crypt = nullptr;
                // crypt.open(&handle_crypt, enc_crypt_alg, enc_crypt_mode, &cek[0], cek.size(), &iv[0], iv.size());
                // /* Content Encryption */
                // ret = crypt.decrypt2(handle_crypt, &ciphertext[0], ciphertext.size(), output, &aad, &tag);
                // crypt.close(handle_crypt);
                ret = crypt.decrypt(enc_crypt_alg, enc_crypt_mode, cek, iv, ciphertext, output, aad, tag);
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t json_object_encryption::check_constraints(jwa_t alg, const EVP_PKEY* pkey) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        /*
         * RFC7518 4.2.  Key Encryption with RSAES-PKCS1-v1_5
         * RFC7518 4.3.  Key Encryption with RSAES OAEP
         * A key of size 2048 bits or larger MUST be used with this algorithm.
         */
        switch (alg) {
            case jwa_t::jwa_rsa_1_5:
            case jwa_t::jwa_rsa_oaep:
            case jwa_t::jwa_rsa_oaep_256: {
                int bits = EVP_PKEY_bits(pkey);
                if (bits < 2048) {
                    ret = errorcode_t::low_security;
                    __leave2;
                }
            } break;
            default:
                break;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

json_object_encryption::composer::composer() {}

return_t json_object_encryption::composer::compose_encryption(jose_context_t* handle, std::string& output, jose_serialization_t type) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        output.clear();

        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (handle->encryptions.empty()) {
            ret = errorcode_t::no_data;
            __leave2;
        }

        jose_encryptions_map_t::iterator eit = handle->encryptions.begin();
        jose_encryption_t& encryption = eit->second;
        if (encryption.recipients.empty()) {
            __leave2;
        }

        jose_recipients_t::iterator rit = encryption.recipients.begin();
        jose_recipient_t& recipient = rit->second;

        std::string b64_header;
        std::string b64_iv;
        std::string b64_tag;
        std::string b64_ciphertext;
        std::string b64_encryptedkey;

        b64_header = base64_encode((byte_t*)encryption.header.c_str(), encryption.header.size(), base64_encoding_t::base64url_encoding);
        b64_iv = base64_encode(&encryption.datamap[crypt_item_t::item_iv][0], encryption.datamap[crypt_item_t::item_iv].size(),
                               base64_encoding_t::base64url_encoding);
        b64_tag = base64_encode(&encryption.datamap[crypt_item_t::item_tag][0], encryption.datamap[crypt_item_t::item_tag].size(),
                                base64_encoding_t::base64url_encoding);
        b64_ciphertext = base64_encode(&encryption.datamap[crypt_item_t::item_ciphertext][0], encryption.datamap[crypt_item_t::item_ciphertext].size(),
                                       base64_encoding_t::base64url_encoding);

        if (jose_serialization_t::jose_compact == type) {
            b64_encryptedkey = base64_encode(&recipient.datamap[crypt_item_t::item_encryptedkey][0], recipient.datamap[crypt_item_t::item_encryptedkey].size(),
                                             base64_encoding_t::base64url_encoding);

            output += b64_header;
            output += ".";
            output += b64_encryptedkey;
            output += ".";
            output += b64_iv;
            output += ".";
            output += b64_ciphertext;
            output += ".";
            output += b64_tag;
        } else if (jose_serialization_t::jose_flatjson == type) {
            b64_encryptedkey = base64_encode(&recipient.datamap[crypt_item_t::item_encryptedkey][0], recipient.datamap[crypt_item_t::item_encryptedkey].size(),
                                             base64_encoding_t::base64url_encoding);

            json_t* json_serialization = nullptr;
            __try2 {
                json_serialization = json_object();
                if (nullptr == json_serialization) {
                    ret = errorcode_t::internal_error;
                    __leave2;
                }
                json_object_set_new(json_serialization, "protected", json_string(b64_header.c_str()));
                json_object_set_new(json_serialization, "encrypted_key", json_string(b64_encryptedkey.c_str()));
                json_object_set_new(json_serialization, "iv", json_string(b64_iv.c_str()));
                json_object_set_new(json_serialization, "ciphertext", json_string(b64_ciphertext.c_str()));
                json_object_set_new(json_serialization, "tag", json_string(b64_tag.c_str()));

                char* contents = json_dumps(json_serialization, JOSE_JSON_FORMAT);
                if (nullptr != contents) {
                    output = contents;
                    free(contents);
                } else {
                    ret = errorcode_t::internal_error;
                    __leave2;
                }
            }
            __finally2 {
                if (json_serialization) {
                    json_decref(json_serialization);
                }
            }
        } else if (jose_serialization_t::jose_json == type) {
            json_t* json_serialization = nullptr;
            json_t* json_recipients = nullptr;
            json_t* json_recipient = nullptr;
            __try2 {
                json_serialization = json_object();
                if (nullptr == json_serialization) {
                    ret = errorcode_t::internal_error;
                    __leave2;
                }
                json_recipients = json_array();
                if (nullptr == json_recipients) {
                    ret = errorcode_t::internal_error;
                    __leave2;
                }
                json_object_set_new(json_serialization, "protected", json_string(b64_header.c_str()));
                for (jose_recipients_t::iterator rit = encryption.recipients.begin(); rit != encryption.recipients.end(); rit++) {
                    jwa_t alg = rit->first;

                    jose_recipient_t& recipient = rit->second;

                    json_recipient = json_object();
                    if (json_recipient) {
                        json_t* header = json_object();
                        if (header) {
                            const hint_jose_encryption_t* hint = advisor->hintof_jose_algorithm(alg);
                            json_object_set_new(header, "alg", json_string(hint->alg_name));
                            if (recipient.kid.size()) {
                                json_object_set_new(header, "kid", json_string(recipient.kid.c_str()));
                            }

                            uint32 alg_group = hint->group;
                            if ((jwa_group_t::jwa_group_ecdh == alg_group) || (jwa_group_t::jwa_group_ecdh_aeskw == alg_group)) {
                                binary_t pub1;
                                binary_t pub2;
                                const EVP_PKEY* epk = recipient.epk;
                                crypto_key::get_public_key(epk, pub1, pub2);
                                json_t* json_epk = json_object();
                                if (json_epk) {
                                    std::string kty;
                                    std::string curve_name;
                                    advisor->ktyof_ec_curve(epk, kty);
                                    advisor->nameof_ec_curve(epk, curve_name);

                                    json_object_set_new(json_epk, "kty", json_string(kty.c_str()));
                                    json_object_set_new(json_epk, "crv", json_string(curve_name.c_str()));
                                    json_object_set_new(json_epk, "x",
                                                        json_string(base64_encode(&pub1[0], pub1.size(), base64_encoding_t::base64url_encoding).c_str()));
                                    if (pub2.size()) {
                                        json_object_set_new(json_epk, "y",
                                                            json_string(base64_encode(&pub2[0], pub2.size(), base64_encoding_t::base64url_encoding).c_str()));
                                    }
                                    json_object_set_new(header, "epk", json_epk);
                                }
                            } else if (jwa_group_t::jwa_group_aesgcmkw == alg_group) {
                                std::string b64_iv = base64_encode(&recipient.datamap[crypt_item_t::item_iv][0],
                                                                   recipient.datamap[crypt_item_t::item_iv].size(), base64_encoding_t::base64url_encoding);
                                std::string b64_tag = base64_encode(&recipient.datamap[crypt_item_t::item_tag][0],
                                                                    recipient.datamap[crypt_item_t::item_tag].size(), base64_encoding_t::base64url_encoding);
                                json_object_set_new(header, "iv", json_string(b64_iv.c_str()));
                                json_object_set_new(header, "tag", json_string(b64_tag.c_str()));
                            } else if (jwa_group_t::jwa_group_pbes_hs_aeskw == alg_group) {
                                std::string b64_p2s = base64_encode(&recipient.datamap[crypt_item_t::item_p2s][0],
                                                                    recipient.datamap[crypt_item_t::item_p2s].size(), base64_encoding_t::base64url_encoding);
                                json_object_set_new(header, "p2s", json_string(b64_p2s.c_str()));
                                json_object_set_new(header, "p2c", json_integer(recipient.p2c));
                            }

                            json_object_set_new(json_recipient, "header", header);
                        }

                        b64_encryptedkey = base64_encode(&recipient.datamap[crypt_item_t::item_encryptedkey][0],
                                                         recipient.datamap[crypt_item_t::item_encryptedkey].size(), base64_encoding_t::base64url_encoding);
                        json_object_set_new(json_recipient, "encrypted_key", json_string(b64_encryptedkey.c_str()));

                        json_array_append_new(json_recipients, json_recipient);
                    }
                }
                json_object_set_new(json_serialization, "recipients", json_recipients);
                json_object_set_new(json_serialization, "iv", json_string(b64_iv.c_str()));
                json_object_set_new(json_serialization, "ciphertext", json_string(b64_ciphertext.c_str()));
                json_object_set_new(json_serialization, "tag", json_string(b64_tag.c_str()));

                char* contents = json_dumps(json_serialization, JOSE_JSON_FORMAT);
                if (nullptr != contents) {
                    output = contents;
                    free(contents);
                } else {
                    ret = errorcode_t::internal_error;
                    __leave2;
                }
            }
            __finally2 {
                if (json_serialization) {
                    json_decref(json_serialization);
                }
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t json_object_encryption::composer::compose_encryption_aead_header(std::string const& source_encoded, binary_t const& tag, binary_t& aad,
                                                                          std::string& output_encoded) {
    return_t ret = errorcode_t::success;
    json_t* json_header = nullptr;

    output_encoded.clear();

    /* compact, flattened */
    // protected_header
    json_open_stream(&json_header, source_encoded.c_str(), true);
    if (json_header) {
        const char* alg_value = nullptr;
        const char* tag_value = nullptr;
        json_unpack(json_header, "{s:s}", "alg", &alg_value);
        json_unpack(json_header, "{s:s}", "tag", &tag_value);
        if (alg_value) {
            if ((nullptr == tag_value) || (tag_value && (0 == strlen(tag_value)))) {
                std::string tag_encoded;
                tag_encoded = base64_encode(&tag[0], tag.size(), base64_encoding_t::base64url_encoding);

                json_object_set_new(json_header, "tag", json_string(tag_encoded.c_str()));
                char* contents = json_dumps(json_header, JOSE_JSON_FORMAT);
                if (nullptr != contents) {
                    std::string header = contents;
                    base64_encode((byte_t*)header.c_str(), header.size(), aad, base64_encoding_t::base64url_encoding);  // update for encryption
                    output_encoded = header;                                                                            // update for JWE.output
                    free(contents);
                }
            }
        }
        json_decref(json_header);
    }
    return ret;
}

return_t json_object_encryption::composer::compose_encryption_dorandom(jose_context_t* handle, jwe_t enc, std::list<jwa_t> const& algs) {
    return_t ret = errorcode_t::success;
    openssl_prng rand;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (algs.empty()) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        jose_encryptions_map_t::iterator iter = handle->encryptions.find(enc);
        if (handle->encryptions.end() == iter) {
            const hint_jose_encryption_t* enc_hint = advisor->hintof_jose_encryption(enc);  // content encryption
            if (nullptr == enc_hint) {
                ret = errorcode_t::not_supported;
                __leave2;
            }

            const EVP_CIPHER* enc_evp_cipher = advisor->find_evp_cipher(enc_hint->crypt_alg, enc_hint->crypt_mode);
            if (nullptr == enc_evp_cipher) {
                ret = errorcode_t::internal_error;
                __leave2;
            }

            uint32 enc_group = enc_hint->group;
            int keysize = EVP_CIPHER_key_length(enc_evp_cipher);
            int ivsize = EVP_CIPHER_iv_length(enc_evp_cipher);
            /* EVP_CIPHER_CTX_key_length, EVP_CIPHER_CTX_iv_length
             * [openssl 3.0.3] compatibility problem
             * EVP_CIPHER_..._length return EVP_CTRL_RET_UNSUPPORTED(-1)
             */
            adjust_range(keysize, 0, EVP_MAX_KEY_LENGTH);
            adjust_range(ivsize, 0, EVP_MAX_IV_LENGTH);
            if (jwe_group_t::jwe_group_aescbc_hs == enc_group) {
                keysize *= 2;
            }

            jose_encryption_t item;
            item.enc_info = enc_hint;

            /* generate cek if not included "dir", "ECDH-ES" */
            rand.random(item.datamap[crypt_item_t::item_cek], keysize);
            rand.random(item.datamap[crypt_item_t::item_iv], ivsize);

            binary_t protected_header;

            if (1 == algs.size()) {
                jwa_t alg = algs.front();

                // const hint_jose_encryption_t* alg_hint = advisor->hintof_jose_algorithm (alg);  // key management
                std::string kid;
                const EVP_PKEY* pkey = handle->key->select(kid, alg, crypto_use_t::use_enc);
                if (nullptr == pkey) {
                    ret = errorcode_t::not_found;
                    __leave2;
                }

                crypt_datamap_t datamap;
                crypt_variantmap_t variantmap;
                jose_recipient_t recipient;
                docompose_encryption_recipient_random(alg, pkey, recipient, datamap, variantmap);

                binary_t header;
                docompose_encryption_header_parameter(protected_header, enc, alg, jose_compose_t::jose_enc_alg, kid, datamap, variantmap, handle->flags);
                docompose_encryption_header_parameter(header, jwe_t::jwe_unknown, alg, jose_compose_t::jose_alg_only, kid, datamap, variantmap);

                item.header.assign((char*)&protected_header[0], protected_header.size());
                base64_encode(&protected_header[0], protected_header.size(), item.datamap[crypt_item_t::item_aad], base64_encoding_t::base64url_encoding);

                recipient.header = std::string((char*)&header[0], header.size());
                recipient.kid = kid;
                item.recipients.insert(std::make_pair(alg, recipient));
            } else if (algs.size() > 1) {
                docompose_protected_header(protected_header, enc, jwa_t::jwa_unknown, jose_compose_t::jose_enc_only, "", handle->flags);
                item.header.assign((char*)&protected_header[0], protected_header.size());
                base64_encode(&protected_header[0], protected_header.size(), item.datamap[crypt_item_t::item_aad], base64_encoding_t::base64url_encoding);

                for (std::list<jwa_t>::const_iterator iter = algs.begin(); iter != algs.end(); iter++) {
                    jwa_t alg = *iter;

                    // const hint_jose_encryption_t* alg_hint = advisor->hintof_jose_algorithm (alg);  // key management
                    std::string kid;
                    const EVP_PKEY* pkey = handle->key->select(kid, alg, crypto_use_t::use_enc);

                    crypt_datamap_t datamap;
                    crypt_variantmap_t variantmap;
                    jose_recipient_t recipient;

                    recipient.kid = kid;
                    docompose_encryption_recipient_random(alg, pkey, recipient, datamap, variantmap);

                    binary_t header;
                    docompose_encryption_header_parameter(header, jwe_t::jwe_unknown, alg, jose_compose_t::jose_alg_only, kid, datamap, variantmap);
                    recipient.header = std::string((char*)&header[0], header.size());
                    item.recipients.insert(std::make_pair(alg, recipient));
                }
            }

            handle->protected_header = protected_header;
            handle->encryptions.insert(std::make_pair(enc, item));
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t json_object_encryption::composer::docompose_protected_header(binary_t& header, jwe_t enc, jwa_t alg, jose_compose_t flag, std::string const& kid,
                                                                      uint32 flags) {
    return_t ret = errorcode_t::success;
    crypt_datamap_t datamap;
    crypt_variantmap_t variantmap;

    ret = docompose_encryption_header_parameter(header, enc, alg, flag, kid, datamap, variantmap, flags);
    return ret;
}

return_t json_object_encryption::composer::docompose_encryption_header_parameter(binary_t& header, jwe_t enc, jwa_t alg, jose_compose_t flag,
                                                                                 std::string const& kid, crypt_datamap_t& datamap,
                                                                                 crypt_variantmap_t& variantmap, uint32 flags) {
    return_t ret = errorcode_t::success;
    json_t* json_header = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        header.clear();

        if (0 == (jose_compose_t::jose_enc_alg & flag)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const char* enc_value = advisor->nameof_jose_encryption(enc);
        const char* alg_value = advisor->nameof_jose_algorithm(alg);

        json_header = json_object();

        if (jose_compose_t::jose_enc_only & flag) {
            // const hint_jose_encryption_t* enc_hint = advisor->hintof_jose_encryption(enc);
            if (nullptr == enc_value) {
                ret = errorcode_t::invalid_parameter;
                __leave2;
            }
            json_object_set_new(json_header, "enc", json_string(enc_value));
        }
        if (jose_compose_t::jose_alg_only & flag) {
            const hint_jose_encryption_t* alg_hint = advisor->hintof_jose_algorithm(alg);
            if (nullptr == alg_hint) {
                ret = errorcode_t::not_supported;
                __leave2;
            }
            uint32 alg_group = alg_hint->group;

            json_object_set_new(json_header, "alg", json_string(alg_value));
            if (kid.size()) {
                json_object_set_new(json_header, "kid", json_string(kid.c_str()));
            }
            if ((jwa_group_t::jwa_group_ecdh == alg_group) || (jwa_group_t::jwa_group_ecdh_aeskw == alg_group)) {
                // epk, apu, apv
                binary_t pub1;
                binary_t pub2;
                const EVP_PKEY* epk = (const EVP_PKEY*)variantmap[crypt_item_t::item_epk].data.p;
                crypto_key::get_public_key(epk, pub1, pub2);
                json_t* json_epk = json_object();
                if (json_epk) {
                    std::string kty;
                    std::string curve_name;
                    advisor->ktyof_ec_curve(epk, kty);
                    advisor->nameof_ec_curve(epk, curve_name);

                    json_object_set_new(json_epk, "kty", json_string(kty.c_str()));
                    json_object_set_new(json_epk, "crv", json_string(curve_name.c_str()));
                    json_object_set_new(json_epk, "x", json_string(base64_encode(&pub1[0], pub1.size(), base64_encoding_t::base64url_encoding).c_str()));
                    if (pub2.size()) {
                        json_object_set_new(json_epk, "y", json_string(base64_encode(&pub2[0], pub2.size(), base64_encoding_t::base64url_encoding).c_str()));
                    }
                    json_object_set_new(json_header, "epk", json_epk);
                }
            } else if (jwa_group_t::jwa_group_aesgcmkw == alg_group) {
                // iv, tag
                binary_t iv1 = datamap[crypt_item_t::item_iv];
                binary_t tag1 = datamap[crypt_item_t::item_tag];
                json_object_set_new(json_header, "iv", json_string(base64_encode(&iv1[0], iv1.size(), base64_encoding_t::base64url_encoding).c_str()));
                json_object_set_new(json_header, "tag", json_string(base64_encode(&tag1[0], tag1.size(), base64_encoding_t::base64url_encoding).c_str()));
            } else if (jwa_group_t::jwa_group_pbes_hs_aeskw == alg_group) {
                // p2s, p2c
                binary_t p2s = datamap[crypt_item_t::item_p2s];
                uint32 p2c = variantmap[crypt_item_t::item_p2c].data.i32;
                json_object_set_new(json_header, "p2s", json_string(base64_encode(&p2s[0], p2s.size(), base64_encoding_t::base64url_encoding).c_str()));
                json_object_set_new(json_header, "p2c", json_integer(p2c));
            }
        }
        if (flags & jose_flag_t::jose_deflate) {
            json_object_set_new(json_header, "zip", json_string("DEF"));
        }

        char* contents = json_dumps(json_header, JOSE_JSON_FORMAT);
        if (nullptr != contents) {
            header.insert(header.end(), (byte_t*)contents, (byte_t*)contents + strlen(contents));
            free(contents);
        } else {
            ret = errorcode_t::internal_error;
            __leave2;
        }
    }
    __finally2 {
        if (json_header) {
            json_decref(json_header);
        }
    }

    return ret;
}

return_t json_object_encryption::composer::docompose_encryption_recipient_random(jwa_t alg, const EVP_PKEY* pkey, jose_recipient_t& recipient,
                                                                                 crypt_datamap_t& datamap, crypt_variantmap_t& variantmap) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    const hint_jose_encryption_t* alg_hint = advisor->hintof_jose_algorithm(alg);  // key management
    uint32 alg_group = alg_hint->group;

    recipient.alg_info = alg_hint;

    if ((jwa_group_t::jwa_group_ecdh == alg_group) || (jwa_group_t::jwa_group_ecdh_aeskw == alg_group)) {
        // epk
        uint32 nid = 0;
        crypto_key key;
        crypto_keychain keyset;
        std::string kid;
        nidof_evp_pkey(pkey, nid);                                // "crv" of key
        keyset.add_ec(&key, nid);                                 // same "crv"
        recipient.epk = key.select(crypto_use_t::use_enc, true);  // EVP_PKEY_up_ref
        variant_t vt;
        variant_set_pointer(vt, recipient.epk);
        variantmap[crypt_item_t::item_epk] = vt;
    } else if (jwa_group_t::jwa_group_aesgcmkw == alg_group) {
        // iv, tag
        const EVP_CIPHER* alg_evp_cipher = advisor->find_evp_cipher(alg_hint->crypt_alg, alg_hint->crypt_mode);
        int ivsize = EVP_CIPHER_iv_length(alg_evp_cipher);
        openssl_prng rand;
        rand.random(recipient.datamap[crypt_item_t::item_iv], ivsize);
        datamap[crypt_item_t::item_iv] = recipient.datamap[crypt_item_t::item_iv];
        datamap[crypt_item_t::item_tag] = recipient.datamap[crypt_item_t::item_tag];
    } else if (jwa_group_t::jwa_group_pbes_hs_aeskw == alg_group) {
        // p2s, p2c
        openssl_prng rand;
        rand.random(recipient.datamap[crypt_item_t::item_p2s], 64);
        rand.random(recipient.p2c, 0xffff);
        variant_t vt;
        variant_set_int32(vt, recipient.p2c);
        datamap[crypt_item_t::item_p2s] = recipient.datamap[crypt_item_t::item_p2s];
        variantmap[crypt_item_t::item_p2c] = vt;
    }
    return ret;
}

static void json_unpack_helper(std::list<json_t*> const& pool, const char* key, const char** ptr) {
    const char* value = nullptr;
    int ret = 0;

    __try2 {
        if (nullptr == key || nullptr == ptr) {
            __leave2;
        }

        std::list<json_t*>::const_iterator iter;
        for (iter = pool.begin(); iter != pool.end(); iter++) {
            ret = json_unpack(*iter, "{s:s}", key, &value);
            if (0 == ret) {
                *ptr = value;
                break;
            }
        }
    }
    __finally2 {
        // do nothing
    }
}

static void json_unpack_helper(std::list<json_t*> const& pool, const char* key, int* ptr) {
    int value = 0;
    int ret = 0;

    __try2 {
        if (nullptr == key || nullptr == ptr) {
            __leave2;
        }

        std::list<json_t*>::const_iterator iter;
        for (iter = pool.begin(); iter != pool.end(); iter++) {
            ret = json_unpack(*iter, "{s:i}", key, &value);
            if (0 == ret) {
                *ptr = value;
                break;
            }
        }
    }
    __finally2 {
        // do nothing
    }
}

static void json_unpack_helper(std::list<json_t*> const& pool, const char* key, json_t** ptr) {
    json_t* value = nullptr;
    int ret = 0;

    __try2 {
        if (nullptr == key || nullptr == ptr) {
            __leave2;
        }

        std::list<json_t*>::const_iterator iter;
        for (iter = pool.begin(); iter != pool.end(); iter++) {
            ret = json_unpack(*iter, "{s:o}", key, &value);
            if (0 == ret) {
                *ptr = value;
                break;
            }
        }
    }
    __finally2 {
        // do nothing
    }
}

return_t json_object_encryption::composer::parse_decryption(jose_context_t* handle, const char* input) {
    return_t ret = errorcode_t::success;
    json_t* json_root = nullptr;
    split_context_t* split_handle = nullptr;

    __try2 {
        if (nullptr == handle || nullptr == input) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        return_t ret_test = json_open_stream(&json_root, input, true);
        if (errorcode_t::success == ret_test) {
            jose_encryption_t item;

            json_t* json_recipients = nullptr;
            json_unpack(json_root, "{s:o}", "recipients", &json_recipients);

            if (json_recipients) {  // jose_serialization_t::jose_json
                if (json_is_array(json_recipients)) {
                    const char* protected_header = nullptr;
                    const char* iv = nullptr;
                    const char* ciphertext = nullptr;
                    const char* tag = nullptr;

                    json_unpack(json_root, "{s:s}", "protected", &protected_header);
                    json_unpack(json_root, "{s:s,s:s,s:s}", "iv", &iv, "ciphertext", &ciphertext, "tag", &tag);

                    jwe_t enc_type = jwe_t::jwe_unknown;
                    doparse_decryption(handle, protected_header, nullptr, iv, ciphertext, tag, json_root, enc_type, item);

                    size_t array_size = json_array_size(json_recipients);
                    for (size_t index = 0; index < array_size; index++) {
                        json_t* json_recipient = json_array_get(json_recipients, index);
                        json_t* json_header = nullptr;
                        jose_recipient_t recipient;
                        jwa_t alg_type = jwa_t::jwa_unknown;

                        const char* encrypted_key = nullptr;
                        // char* header = nullptr;

                        json_unpack(json_recipient, "{s:o}", "header", &json_header);
                        json_unpack(json_recipient, "{s:s}", "encrypted_key", &encrypted_key);

                        doparse_decryption_recipient(handle, protected_header, encrypted_key, json_root, json_header, alg_type, recipient);
                        item.recipients.insert(std::make_pair(alg_type, recipient));
                    }
                    handle->encryptions.insert(std::make_pair(enc_type, item));
                } else {
                    ret = errorcode_t::bad_data;
                    __leave2;
                }
            } else {  // jose_serialization_t::jose_flatjson
                const char* protected_header = nullptr;
                const char* encrypted_key = nullptr;
                const char* iv = nullptr;
                const char* ciphertext = nullptr;
                const char* tag = nullptr;

                json_unpack(json_root, "{s:s}", "protected", &protected_header);
                json_unpack(json_root, "{s:s,s:s,s:s}", "iv", &iv, "ciphertext", &ciphertext, "tag", &tag);
                json_unpack(json_root, "{s:s}", "encrypted_key", &encrypted_key);  // not exist in case of "dir", "ECDH-ES"

                jose_recipient_t recipient;
                jwe_t enc_type = jwe_t::jwe_unknown;
                jwa_t alg_type = jwa_t::jwa_unknown;
                doparse_decryption(handle, protected_header, encrypted_key, iv, ciphertext, tag, json_root, enc_type, item);
                doparse_decryption_recipient(handle, protected_header, encrypted_key, json_root, nullptr, alg_type, recipient);

                item.recipients.insert(std::make_pair(alg_type, recipient));
                handle->encryptions.insert(std::make_pair(enc_type, item));
            }
        } else {  // jose_serialization_t::jose_compact
            size_t count = 0;
            split_begin(&split_handle, input, ".");
            split_count(split_handle, count);
            if (5 != count) {
                ret = errorcode_t::bad_data;
                __leave2;
            }

            std::string protected_header;
            std::string encrypted_key;
            std::string iv;
            std::string ciphertext;
            std::string tag;

            /* base64url encoded */
            split_get(split_handle, 0, protected_header);
            split_get(split_handle, 1, encrypted_key);
            split_get(split_handle, 2, iv);
            split_get(split_handle, 3, ciphertext);
            split_get(split_handle, 4, tag);

            jose_encryption_t item;
            jose_recipient_t recipient;
            jwe_t enc_type = jwe_t::jwe_unknown;
            jwa_t alg_type = jwa_t::jwa_unknown;
            doparse_decryption(handle, protected_header.c_str(), encrypted_key.c_str(), iv.c_str(), ciphertext.c_str(), tag.c_str(), nullptr, enc_type, item);
            doparse_decryption_recipient(handle, protected_header.c_str(), encrypted_key.c_str(), nullptr, nullptr, alg_type, recipient);

            item.recipients.insert(std::make_pair(alg_type, recipient));
            handle->encryptions.insert(std::make_pair(enc_type, item));
        }
    }
    __finally2 {
        if (split_handle) {
            split_end(split_handle);
        }
        if (json_root) {
            json_decref(json_root);
        }
    }
    return ret;
}

return_t json_object_encryption::composer::doparse_decryption(jose_context_t* handle, const char* protected_header, const char* encrypted_key, const char* iv,
                                                              const char* ciphertext, const char* tag, void* json_t_root, jwe_t& type,
                                                              jose_encryption_t& item) {
    return_t ret = errorcode_t::success;
    json_t* json_protected = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    json_t* json_root = (json_t*)json_t_root;
    std::list<json_t*> pool;

    __try2 {
        type = jwe_t::jwe_unknown;

        // protected can be nullptr
        // see RFC 7520 5.12.  Protecting Content Only
        std::string protected_header_decoded;
        const char* enc = nullptr;
        if (protected_header) {
            protected_header_decoded = base64_decode_careful(protected_header, strlen(protected_header), base64_encoding_t::base64url_encoding);
            ret = json_open_stream(&json_protected, protected_header_decoded.c_str(), true);
            if (errorcode_t::success != ret) {
                __leave2;
            }

            pool.push_back(json_protected);
        }

        if (json_root) {
            // RFC 7520 5.10.  Including Additional Authenticated Data
            // only the flattened JWE JSON Serialization and general JWE JSON Serialization are possible.
            // check - test failed !!
            const char* aad = nullptr;
            json_unpack(json_root, "{s:s}", "aad", &aad);
            if (aad) {
                // Concatenation of the JWE Protected Header ".", and the base64url [RFC4648] encoding of AAD as authenticated data
                binary_t bin_aad;
                bin_aad.insert(bin_aad.end(), protected_header, protected_header + strlen(protected_header));
                bin_aad.insert(bin_aad.end(), '.');
                bin_aad.insert(bin_aad.end(), aad, aad + strlen(aad));
                item.datamap[crypt_item_t::item_aad] = bin_aad;
            }

            // RFC 7520 5.12.  Protecting Content Only
            // only the general JWE JSON Serialization and flattened JWE JSON Serialization are possible.
            json_t* unprotected_header = nullptr;
            json_unpack(json_root, "{s:o}", "unprotected", &unprotected_header);
            if (unprotected_header) {
                pool.push_back(unprotected_header);
            }
        }

        json_unpack_helper(pool, "enc", &enc);

        const hint_jose_encryption_t* enc_hint = advisor->hintof_jose_encryption(enc);
        if (nullptr == enc_hint) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        type = (jwe_t)enc_hint->type;
        item.enc_info = enc_hint;

        // do not update if crypt_item_t::item_aad already exists
        // see RFC 7520 5.10.  Including Additional Authenticated Data
        if (protected_header) {
            item.datamap.insert(std::make_pair(crypt_item_t::item_aad, convert(protected_header)));
        }

        item.header = protected_header_decoded;
        base64_decode(iv, strlen(iv), item.datamap[crypt_item_t::item_iv], base64_encoding_t::base64url_encoding);
        base64_decode(tag, strlen(tag), item.datamap[crypt_item_t::item_tag], base64_encoding_t::base64url_encoding);
        base64_decode(ciphertext, strlen(ciphertext), item.datamap[crypt_item_t::item_ciphertext], base64_encoding_t::base64url_encoding);

        const char* zip = nullptr;
        json_unpack_helper(pool, "zip", &zip);
        if (zip) {
            // RFC 7520 5.9.  Compressed Content
            item.datamap[crypt_item_t::item_zip] = convert(zip);
        }
    }
    __finally2 {
        if (json_protected) {
            json_decref(json_protected);
        }
    }
    return ret;
}

return_t json_object_encryption::composer::doparse_decryption_recipient(jose_context_t* handle, const char* protected_header, const char* encrypted_key,
                                                                        void* json_t_root, void* json_t_recipient_header, jwa_t& type,
                                                                        jose_recipient_t& recipient) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    std::list<json_t*> pool;

    json_t* json_root = (json_t*)json_t_root;
    json_t* json_recipient_header = (json_t*)json_t_recipient_header;
    json_t* json_protected = nullptr;

    __try2 {
        recipient.datamap[crypt_item_t::item_encryptedkey].clear();

        type = jwa_t::jwa_unknown;

        return_t ret_test = errorcode_t::success;

        if (json_recipient_header) {
            pool.push_back(json_recipient_header);
        }
        if (protected_header) {
            // protected can be nullptr
            // see RFC 7520 5.12.  Protecting Content Only
            std::string protected_header_decoded = base64_decode_careful(protected_header, strlen(protected_header), base64_encoding_t::base64url_encoding);
            ret_test = json_open_stream(&json_protected, protected_header_decoded.c_str(), true);
            if (errorcode_t::success != ret_test) {
                ret = errorcode_t::bad_data;
                __leave2;
            }
            pool.push_back(json_protected);
        }
        if (json_root) {
            // RFC 7520 5.12.  Protecting Content Only
            // only the general JWE JSON Serialization and flattened JWE JSON Serialization are possible.
            json_t* unprotected_header = nullptr;
            json_unpack(json_root, "{s:o}", "unprotected", &unprotected_header);
            if (unprotected_header) {
                pool.push_back(unprotected_header);
            }
        }

        const char* enc = nullptr;
        json_unpack_helper(pool, "enc", &enc);

        const hint_jose_encryption_t* enc_hint = advisor->hintof_jose_encryption(enc);
        if (nullptr == enc_hint) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        const char* enckey = nullptr;
        if (encrypted_key) {
            enckey = encrypted_key;
        } else {
            json_unpack_helper(pool, "encrypted_key", &enckey);
        }
        if (enckey) {
            base64_decode(enckey, strlen(enckey), recipient.datamap[crypt_item_t::item_encryptedkey], base64_encoding_t::base64url_encoding);
        }

        const char* alg = nullptr;
        const char* kid = nullptr;
        json_unpack_helper(pool, "alg", &alg);
        json_unpack_helper(pool, "kid", &kid);
        const hint_jose_encryption_t* alg_hint = advisor->hintof_jose_algorithm(alg);
        if (nullptr == alg_hint) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        recipient.alg_info = alg_hint;
        if (kid) {
            recipient.kid = kid;
        }

        type = (jwa_t)alg_hint->type;
        uint32 alg_group = alg_hint->group;
        if ((jwa_group_t::jwa_group_ecdh == alg_group) || (jwa_group_t::jwa_group_ecdh_aeskw == alg_group)) {  // epk
            json_t* epk = nullptr;
            const char* apu_value = nullptr;
            const char* apv_value = nullptr;
            json_unpack_helper(pool, "epk", &epk);
            json_unpack_helper(pool, "apu", &apu_value);
            json_unpack_helper(pool, "apv", &apv_value);

            const char* kty_value = nullptr;
            const char* crv_value = nullptr;
            const char* x_value = nullptr;
            const char* y_value = nullptr;

            if (epk) {
                json_unpack(epk, "{s:s,s:s,s:s,s:s}", "kty", &kty_value, "crv", &crv_value, "x", &x_value, "y", &y_value);
                if (nullptr == kty_value || nullptr == crv_value || nullptr == x_value) {
                    ret = errorcode_t::bad_data;
                    __leave2;
                }
            } else {
                ret = errorcode_t::bad_data;
                __leave2;
            }

            json_web_key jwk;
            crypto_key key;
            jwk.add_ec_b64u(&key, nullptr, nullptr, crv_value, x_value, y_value, nullptr);
            recipient.epk = key.select(crypto_use_t::use_enc, true);  // EVP_PKEY_up_ref
            if (apu_value) {
                base64_decode(apu_value, strlen(apu_value), recipient.datamap[crypt_item_t::item_apu], base64_encoding_t::base64url_encoding);
            }
            if (apv_value) {
                base64_decode(apv_value, strlen(apv_value), recipient.datamap[crypt_item_t::item_apv], base64_encoding_t::base64url_encoding);
            }
        } else if (jwa_group_t::jwa_group_aesgcmkw == alg_group) {  // iv, tag
            const char* iv_value = nullptr;
            const char* tag_value = nullptr;
            json_unpack_helper(pool, "iv", &iv_value);
            json_unpack_helper(pool, "tag", &tag_value);

            if (nullptr == iv_value || nullptr == tag_value) {
                ret = errorcode_t::bad_data;
                __leave2;
            }

            base64_decode(iv_value, strlen(iv_value), recipient.datamap[crypt_item_t::item_iv], base64_encoding_t::base64url_encoding);
            base64_decode(tag_value, strlen(tag_value), recipient.datamap[crypt_item_t::item_tag], base64_encoding_t::base64url_encoding);
        } else if (jwa_group_t::jwa_group_pbes_hs_aeskw == alg_group) {  // p2s, p2c
            const char* p2s = nullptr;
            int p2c = -1;
            json_unpack_helper(pool, "p2s", &p2s);
            json_unpack_helper(pool, "p2c", &p2c);

            if (nullptr == p2s || -1 == p2c) {
                ret = errorcode_t::bad_data;
                __leave2;
            }

            base64_decode(p2s, strlen(p2s), recipient.datamap[crypt_item_t::item_p2s], base64_encoding_t::base64url_encoding);
            recipient.p2c = p2c;
        }
    }
    __finally2 {
        if (json_protected) {
            json_decref(json_protected);
        }
    }

    return ret;
}

}  // namespace crypto
}  // namespace hotplace
