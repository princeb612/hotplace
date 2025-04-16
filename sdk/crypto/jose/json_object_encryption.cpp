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

#include <sdk/base/basic/binary.hpp>
#include <sdk/base/string/string.hpp>  // split_begin, split_count, split_get, split_end
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/crypto_cbc_hmac.hpp>
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

namespace hotplace {
namespace crypto {

json_object_encryption::json_object_encryption() {
    // do nothing
}

json_object_encryption::~json_object_encryption() {
    // do nothing
}

return_t json_object_encryption::encrypt(jose_context_t *handle, jwe_t enc, jwa_t alg, const binary_t &input, std::string &output, jose_serialization_t type) {
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

return_t json_object_encryption::encrypt(jose_context_t *handle, jwe_t enc, jwa_t alg, const std::string &input, std::string &output,
                                         jose_serialization_t type) {
    return encrypt(handle, enc, alg, str2bin(input), output, type);
}

return_t json_object_encryption::encrypt(jose_context_t *handle, jwe_t enc, const std::list<jwa_t> &jwalgs, const binary_t &input, std::string &output,
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

        std::list<jwa_t> algs = jwalgs;

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

        for (const jwa_t &alg : algs) {
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

return_t json_object_encryption::encrypt(jose_context_t *handle, jwe_t enc, const std::list<jwa_t> &algs, const std::string &input, std::string &output,
                                         jose_serialization_t type) {
    return encrypt(handle, enc, algs, str2bin(input), output, type);
}

return_t json_object_encryption::decrypt(jose_context_t *handle, const std::string &input, binary_t &output, bool &result) {
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
        for (auto &epair : handle->encryptions) {
            const jwe_t &enc = epair.first;
            jose_encryption_t &item = epair.second;
            binary_t zip;
            t_maphint<crypt_item_t, binary_t> hint(item.datamap);
            hint.find(crypt_item_t::item_zip, &zip);

            for (auto &rpair : item.recipients) {
                const jwa_t &alg = rpair.first;
                bool run = true;

                if (run) {
                    jose_recipient_t &recipient = rpair.second;
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
                        // RFC 7520 5.9.  Compressed Content
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

return_t json_object_encryption::doencrypt(jose_context_t *handle, jwe_t enc, jwa_t alg, const binary_t &input, binary_t &output) {
    return_t ret = errorcode_t::success;
    json_object_encryption::composer composer;
    openssl_crypt crypt;
    openssl_hash hash;
    openssl_kdf kdf;
    crypto_advisor *advisor = crypto_advisor::get_instance();

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

        const hint_jose_encryption_t *alg_hint = advisor->hintof_jose_algorithm(alg);   // key management
        const hint_jose_encryption_t *enc_hint = advisor->hintof_jose_encryption(enc);  // content encryption

        jose_encryption_t &item = iter->second;
        binary_t cek = item.datamap[crypt_item_t::item_cek];                                      // in, enc
        binary_t iv = item.datamap[crypt_item_t::item_iv];                                        // in, enc
        binary_t &aad = item.datamap[crypt_item_t::item_aad];                                     // in, enc
        binary_t &encrypted_key = item.recipients[alg].datamap[crypt_item_t::item_encryptedkey];  // out, alg
        binary_t &tag = item.datamap[crypt_item_t::item_tag];                                     // out, enc
        binary_t &ciphertext = item.datamap[crypt_item_t::item_ciphertext];                       // out, enc

        // alg part - encrypted_key from cek
        {
            const char *alg_name = alg_hint->alg_name;
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
            const EVP_PKEY *pkey = handle->key->select(kid, alg, crypto_use_t::use_enc);
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
                 * RFC7518 4.6. Key Agreement with Elliptic Curve Diffie-Hellman
                 * Ephemeral Static (ECDH-ES)
                 * 1.  directly as the Content Encryption Key (CEK) for the "enc"
                 *     algorithm, in the Direct Key Agreement mode, or
                 * RFC7520 5.5. Key Agreement Using ECDH-ES with AES-CBC-HMAC-SHA2
                 */
                const EVP_PKEY *epk = item.recipients[alg].epk;
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
                 * RFC7518 4.6. Key Agreement with Elliptic Curve Diffie-Hellman
                 * Ephemeral Static (ECDH-ES)
                 * 2.  as a symmetric key used to wrap the CEK with the "A128KW",
                 *     "A192KW", or "A256KW" algorithms, in the Key Agreement with Key Wrapping mode.
                 * RFC7520 5.4. Key Agreement with Key Wrapping Using ECDH-ES and AES-KeyWrap with AES-GCM
                 */
                binary_t derived_key;
                const EVP_PKEY *epk = item.recipients[alg].epk;
                int keylen = alg_hint->keysize;
                uint32 enc_group = enc_hint->group;
                if (jwe_group_t::jwe_group_aescbc_hs == enc_group) {
                    // keylen *= 2;
                }
                ret = ecdh_es(epk, pkey, alg_hint->alg_name, "", "", keylen, derived_key);

                ret = crypt.encrypt(alg_crypt_alg, alg_crypt_mode, derived_key, kw_iv, cek, encrypted_key);
            } else if (jwa_group_t::jwa_group_aesgcmkw == alg_group) {
                /*
                 * A128GCMKW, A192GCMKW, A256GCMKW
                 * RFC7518 4.7. Key Encryption with AES GCM
                 * RFC7520 5.7. Key Wrap Using AES-GCM KeyWrap with AES-CBC-HMAC-SHA2
                 */
                binary_t iv1 = item.recipients[alg].datamap[crypt_item_t::item_iv];
                binary_t aad1;                                                          // empty
                binary_t &tag1 = item.recipients[alg].datamap[crypt_item_t::item_tag];  // compute authencation tag here

                ret = crypt.encrypt(alg_crypt_alg, alg_crypt_mode, oct, iv1, cek, encrypted_key, aad1, tag1);

                /*
                 * tag updated
                 * json serialization - jwe.output using recipient
                 * json flattened, compact - computed tag information must be written in
                 * protected_header
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
                salt.insert(salt.end(), (byte_t *)alg_name, (byte_t *)alg_name + strlen(alg_name));
                salt.insert(salt.end(), 0);
                salt.insert(salt.end(), p2s.begin(), p2s.end());

                /* key derivation
                 * derived_key = PKCS5_PBKDF2_HMAC(passphrase, salt, iteration_count =
                 * p2c, hash)
                 */
                binary_t pbkdf2_derived_key;
                kdf.pbkdf2(pbkdf2_derived_key, alg_hash_alg, alg_keysize, bin2str(oct), salt, p2c);
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
                // RFC 7516 Appendix B.  Example AES_128_CBC_HMAC_SHA_256 Computation
                crypto_cbc_hmac cbchmac;
                cbchmac.set_enc(enc_crypt_alg).set_mac(enc_hash_alg).set_flag(jose_encrypt_then_mac);
                binary_t enckey;
                binary_t mackey;
                cbchmac.split_key(cek, enckey, mackey);
                ret = cbchmac.encrypt(enckey, mackey, iv, aad, input, ciphertext, tag);
            } else if (jwe_group_t::jwe_group_aesgcm == enc_group) {
                ret = crypt.encrypt(enc_crypt_alg, enc_crypt_mode, cek, iv, input, ciphertext, aad, tag);
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t json_object_encryption::dodecrypt(jose_context_t *handle, jwe_t enc, jwa_t alg, const binary_t &input, binary_t &output) {
    return dodecrypt(handle, enc, alg, nullptr, input, output);
}

return_t json_object_encryption::dodecrypt(jose_context_t *handle, jwe_t enc, jwa_t alg, const char *kid, const binary_t &input, binary_t &output) {
    return_t ret = errorcode_t::success;
    openssl_crypt crypt;
    openssl_hash hash;
    openssl_kdf kdf;
    crypto_advisor *advisor = crypto_advisor::get_instance();

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

        const hint_jose_encryption_t *alg_hint = advisor->hintof_jose_algorithm(alg);   // key management
        const hint_jose_encryption_t *enc_hint = advisor->hintof_jose_encryption(enc);  // content encryption

        if (nullptr == alg_hint || nullptr == enc_hint) {
            ret = errorcode_t::bad_request;
            __leave2;
        }

        jose_encryption_t &item = iter->second;
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
            const char *alg_name = alg_hint->alg_name;
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

            const EVP_PKEY *pkey = nullptr;
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
                 * RFC7518 4.6. Key Agreement with Elliptic Curve Diffie-Hellman
                 * Ephemeral Static (ECDH-ES)
                 * 1.  directly as the Content Encryption Key (CEK) for the "enc"
                 *     algorithm, in the Direct Key Agreement mode, or
                 * RFC7520 5.5. Key Agreement Using ECDH-ES with AES-CBC-HMAC-SHA2
                 */
                const EVP_PKEY *epk = item.recipients[alg].epk;
                int keylen = enc_hint->keysize;
                uint32 enc_group = enc_hint->group;
                if (jwe_group_t::jwe_group_aescbc_hs == enc_group) {
                    keylen *= 2;
                }

                ret = ecdh_es(pkey, epk, enc_hint->alg_name, "", "", keylen, cek);
            } else if (jwa_group_t::jwa_group_ecdh_aeskw == alg_group) {
                /*
                 * ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW
                 * RFC7518 4.6. Key Agreement with Elliptic Curve Diffie-Hellman
                 * Ephemeral Static (ECDH-ES)
                 * 2.  as a symmetric key used to wrap the CEK with the "A128KW",
                 *     "A192KW", or "A256KW" algorithms, in the Key Agreement with Key
                 *     Wrapping mode.
                 * RFC7520 5.4. Key Agreement with Key Wrapping Using ECDH-ES and
                 * AES-KeyWrap with AES-GCM
                 */
                binary_t derived_key;
                const EVP_PKEY *epk = item.recipients[alg].epk;
                int keylen = alg_hint->keysize;
                uint32 enc_group = enc_hint->group;
                if (jwe_group_t::jwe_group_aescbc_hs == enc_group) {
                    // keylen *= 2;
                }
                ret = ecdh_es(pkey, epk, alg_hint->alg_name, "", "", keylen, derived_key);

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
                salt.insert(salt.end(), (byte_t *)alg_name, (byte_t *)alg_name + strlen(alg_name));
                salt.insert(salt.end(), 0);
                salt.insert(salt.end(), p2s.begin(), p2s.end());

                /* key derivation
                 * derived_key = PKCS5_PBKDF2_HMAC(passphrase, salt, iteration_count =
                 * p2c, hash)
                 */
                binary_t pbkdf2_derived_key;
                kdf.pbkdf2(pbkdf2_derived_key, alg_hash_alg, alg_keysize, bin2str(oct), salt, p2c);
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
                crypto_cbc_hmac cbchmac;
                cbchmac.set_enc(enc_crypt_alg).set_mac(enc_hash_alg).set_flag(jose_encrypt_then_mac);
                binary_t enckey;
                binary_t mackey;
                cbchmac.split_key(cek, enckey, mackey);
                ret = cbchmac.decrypt(enckey, mackey, iv, aad, ciphertext, output, tag);
            } else if (jwe_group_t::jwe_group_aesgcm == enc_group) {
                ret = crypt.decrypt(enc_crypt_alg, enc_crypt_mode, cek, iv, ciphertext, output, aad, tag);
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t json_object_encryption::check_constraints(jwa_t alg, const EVP_PKEY *pkey) {
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

}  // namespace crypto
}  // namespace hotplace
