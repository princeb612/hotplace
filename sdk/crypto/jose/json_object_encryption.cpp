/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/jose/json_object_encryption.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>
#include <hotplace/sdk/io/system/types.hpp>

#include <hotplace/sdk/io/stream/buffer_stream.hpp>

namespace hotplace {
using namespace io;
namespace crypto {

json_object_encryption::json_object_encryption ()
{
    // do nothing
}

json_object_encryption::~json_object_encryption ()
{
    // do nothing
}

return_t json_object_encryption::encrypt (jose_context_t* context, jwe_t enc, jwa_t alg, binary_t input, binary_t& output)
{
    return_t ret = errorcode_t::success;
    jose_context_t* handle = static_cast <jose_context_t*> (context);
    openssl_crypt crypt;
    openssl_hash hash;
    crypto_advisor* advisor = crypto_advisor::get_instance ();

    __try2
    {
        if (nullptr == context) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace (ret);
        }

        jose_encryptions_map_t::iterator iter = handle->encryptions.find (enc);
        if (handle->encryptions.end () == iter) {
            ret = errorcode_t::internal_error;
            __leave2_trace (ret);
        }

        const hint_jose_encryption_t* alg_info = advisor->hintof_jose_algorithm (alg);      // key management
        const hint_jose_encryption_t* enc_info = advisor->hintof_jose_encryption (enc);     // content encryption

        jose_encryption_t& item = iter->second;
        binary_t cek = item.datamap[crypt_item_t::item_cek];                                        // in, enc
        binary_t iv = item.datamap[crypt_item_t::item_iv];                                          // in, enc
        binary_t& aad = item.datamap[crypt_item_t::item_aad];                                       // in, enc
        binary_t& encrypted_key = item.recipients[alg].datamap[crypt_item_t::item_encryptedkey];    // out, alg
        binary_t& tag = item.datamap[crypt_item_t::item_tag];                                       // out, enc
        binary_t& ciphertext = item.datamap[crypt_item_t::item_ciphertext];                         // out, enc

        // alg part - encrypted_key from cek
        {
            const char* alg_name = alg_info->alg_name;
            crypt_mode2_t crypt_mode = (crypt_mode2_t) alg_info->mode;
            crypt_algorithm_t alg_crypt_alg = (crypt_algorithm_t) alg_info->crypt_alg;
            crypt_mode_t alg_crypt_mode = (crypt_mode_t) alg_info->crypt_mode;
            int alg_keysize = alg_info->keysize;
            hash_algorithm_t alg_hash_alg = (hash_algorithm_t) alg_info->hash_alg;

            binary_t oct;
            /* RFC3394 Advanced Encryption Standard (AES) Key Wrap Algorithm
             * 2.2.3.1 Default Initial Value
             * iv 0xa6 ...
             */
            binary_t kw_iv;
            kw_iv.resize (8);
            memset (&kw_iv[0], 0xa6, kw_iv.size ());

            std::string kid;
            EVP_PKEY* pkey = handle->key->select (kid, alg, crypto_use_t::use_enc);
            if (nullptr == pkey) {
                ret = errorcode_t::not_found;
                __leave2_trace (ret);
            }

            ret = check_constraints (alg, pkey);
            if (errorcode_t::success != ret) {
                __leave2;
            }

            if (crypto_key_t::hmac_key == alg_info->kty) {
                /* EVP_KEY_HMAC key data and length */
                size_t key_length = 0;
                EVP_PKEY_get_raw_private_key ((EVP_PKEY *) pkey, nullptr, &key_length);
                oct.resize (key_length);
                EVP_PKEY_get_raw_private_key ((EVP_PKEY *) pkey, &oct [0], &key_length);
            }

            uint32 alg_type = CRYPT_ALG_TYPE (alg);
            if (jwa_type_t::jwa_type_rsa == alg_type) {
                /*
                 * RSA1_5, RSA-OAEP, RSA-OAEP-256
                 * RFC7518 4.2.  Key Encryption with RSAES-PKCS1-v1_5
                 * A key of size 2048 bits or larger MUST be used with this algorithm.
                 * RFC7518 4.3.  Key Encryption with RSAES OAEP
                 * A key of size 2048 bits or larger MUST be used with this algorithm.
                 * RFC7520 5.1. Key Encryption Using RSA v1.5 and AES-HMAC-SHA2
                 * RFC7520 5.2. Key Encryption Using RSA-OAEP with AES-GCM
                 */
                ret = crypt.encrypt (pkey, cek, encrypted_key, crypt_mode);
            } else if (jwa_type_t::jwa_type_aeskw == alg_type) {
                /*
                 * A128KW, A192KW, A256KW
                 * RFC7518 4.4. Key Wrapping with AES Key Wrap
                 * RFC7520 5.8. Key Wrap Using AES-KeyWrap with AES-GCM
                 */
                crypt_context_t* handle_kw = nullptr;
                crypt.open (&handle_kw, alg_crypt_alg, alg_crypt_mode, &oct[0], oct.size (), &kw_iv[0], kw_iv.size ());
                ret = crypt.encrypt (handle_kw, &cek[0], cek.size (), encrypted_key);
                crypt.close (handle_kw);
            } else if (jwa_type_t::jwa_type_dir == alg_type) {
                /*
                 * dir
                 * RFC7518 4.5. Direct Encryption with a Shared Symmetric Key
                 * RFC7520 5.6. Direct Encryption Using AES-GCM
                 */

                /* read cek from HMAC key and then make it the only one cek */
                cek = oct;
            } else if (jwa_type_t::jwa_type_ecdh == alg_type) {
                /*
                 * ECDH-ES
                 * RFC7518 4.6. Key Agreement with Elliptic Curve Diffie-Hellman Ephemeral Static (ECDH-ES)
                 * 1.  directly as the Content Encryption Key (CEK) for the "enc"
                 *     algorithm, in the Direct Key Agreement mode, or
                 * RFC7520 5.5. Key Agreement Using ECDH-ES with AES-CBC-HMAC-SHA2
                 */
                EVP_PKEY* epk = item.recipients[alg].epk;
                int keylen = enc_info->keysize;
                uint32 enc_type = CRYPT_ENC_TYPE (enc);
                if (jwe_type_t::jwe_type_aescbc_hs == enc_type) {
                    keylen *= 2;
                }

                ret = ecdh_es (epk, pkey, enc_info->alg_name, "", "", keylen, cek);
                encrypted_key = cek;
            } else if (jwa_type_t::jwa_type_ecdh_aeskw == alg_type) {
                /*
                 * ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW
                 * RFC7518 4.6. Key Agreement with Elliptic Curve Diffie-Hellman Ephemeral Static (ECDH-ES)
                 * 2.  as a symmetric key used to wrap the CEK with the "A128KW",
                 *     "A192KW", or "A256KW" algorithms, in the Key Agreement with Key
                 *     Wrapping mode.
                 * RFC7520 5.4. Key Agreement with Key Wrapping Using ECDH-ES and AES-KeyWrap with AES-GCM
                 */
                binary_t derived_key;
                EVP_PKEY* epk = item.recipients[alg].epk;
                int keylen = alg_info->keysize;
                uint32 enc_type = CRYPT_ENC_TYPE (enc);
                if (jwe_type_t::jwe_type_aescbc_hs == enc_type) {
                    //keylen *= 2;
                }
                ret = ecdh_es (epk, pkey, alg_info->alg_name, "", "", keylen, derived_key);

                crypt_context_t* handle_kw = nullptr;
                crypt.open (&handle_kw, alg_crypt_alg, alg_crypt_mode, &derived_key[0], derived_key.size (), &kw_iv[0], kw_iv.size ());
                ret = crypt.encrypt (handle_kw, &cek[0], cek.size (), encrypted_key);
                crypt.close (handle_kw);
            } else if (jwa_type_t::jwa_type_aesgcmkw == alg_type) {
                /*
                 * A128GCMKW, A192GCMKW, A256GCMKW
                 * RFC7518 4.7. Key Encryption with AES GCM
                 * RFC7520 5.7. Key Wrap Using AES-GCM KeyWrap with AES-CBC-HMAC-SHA2
                 */
                binary_t iv1 = item.recipients[alg].datamap[crypt_item_t::item_iv];
                binary_t aad1;                                                          // empty
                binary_t& tag1 = item.recipients[alg].datamap[crypt_item_t::item_tag];  // compute authencation tag here

                crypt_context_t* handle_crypt = nullptr;
                crypt.open (&handle_crypt, alg_crypt_alg, alg_crypt_mode, &oct[0], oct.size (), &iv1[0], iv1.size ());
                ret = crypt.encrypt2 (handle_crypt, &cek[0], cek.size (), encrypted_key, &aad1, &tag1);
                crypt.close (handle_crypt);

                /*
                 * tag updated
                 * json serialization - jwe.output using recipient
                 * json flattened, compact - computed tag information must be written in protected_header
                 */
                if (1 == handle->encryptions.size ()) {
                    /* compact, flattened */
                    json_object_signing_encryption jose;
                    std::string header;
                    jose.update_header (item.header, tag1, aad, header);
                    if (header.size ()) {
                        item.header = header;
                    }
                }

            } else if (jwa_type_t::jwa_type_pbes_hs_aeskw == alg_type) {
                /*
                 * RFC7518 4.8. Key Encryption with PBES2
                 * PBES2-HS256+A128KW, PBES2-HS384+A192KW, PBES2-HS512+A256KW
                 * RFC7520 5.3. Key Wrap Using PBES2-AES-KeyWrap with AES-CBC-HMAC-SHA2
                 */
                binary_t p2s = item.recipients[alg].datamap[crypt_item_t::item_p2s];
                uint32 p2c = item.recipients[alg].p2c;

                const EVP_MD* alg_evp_md = (const EVP_MD*) advisor->find_evp_md (alg_hash_alg);
                binary_t salt;

                /* salt
                 * salt = UTF8(alg) + 0 + BASE64URL_DECODE(p2s)
                 */
                salt.insert (salt.end (), (byte_t*) alg_name, (byte_t*) alg_name + strlen (alg_name));
                salt.insert (salt.end (), 0);
                salt.insert (salt.end (), p2s.begin (), p2s.end ());

                /* key derivation
                 * derived_key = PKCS5_PBKDF2_HMAC(passphrase, salt, iteration_count = p2c, hash)
                 */
                //oct.resize(0);
                binary_t pbkdf2_derived_key;
                pbkdf2_derived_key.resize (alg_keysize);
                PKCS5_PBKDF2_HMAC ((char *) &oct[0], oct.size (), &salt[0], salt.size (), p2c, alg_evp_md,
                                   pbkdf2_derived_key.size (), &pbkdf2_derived_key[0]);

                crypt_context_t* crypt_handle = nullptr;
                crypt.open (&crypt_handle, (crypt_algorithm_t) alg_crypt_alg, alg_crypt_mode,
                            &pbkdf2_derived_key[0], pbkdf2_derived_key.size (), &kw_iv[0], kw_iv.size ());
                ret = crypt.encrypt (crypt_handle, &cek[0], cek.size (), encrypted_key);
                crypt.close (crypt_handle);
            }
        }

        if (errorcode_t::success != ret) {
            __leave2;
        }

        // enc part - ciphertext using cek, iv
        {
            crypt_algorithm_t enc_crypt_alg = (crypt_algorithm_t) enc_info->crypt_alg;
            crypt_mode_t enc_crypt_mode = (crypt_mode_t) enc_info->crypt_mode;
            hash_algorithm_t enc_hash_alg = (hash_algorithm_t) enc_info->hash_alg;

            uint32 enc_type = CRYPT_ENC_TYPE (enc);
            if (jwe_type_t::jwe_type_aescbc_hs == enc_type) {
                int cek_size = cek.size ();
                int64 aad_length = aad.size () * 8;
                int64 al = htonll (aad_length);

                crypt_context_t* handle_crypt = nullptr;
                hash_context_t* handle_hash = nullptr;
                __try2 {
                    ret = crypt.open (&handle_crypt, (crypt_algorithm_t) enc_crypt_alg, (crypt_mode_t) enc_crypt_mode,
                                      &cek[0] + (cek_size / 2), cek_size / 2, &iv[0], iv.size ());
                    if (errorcode_t::success != ret) {
                        __leave2_trace (ret);
                    }

                    /* Content Encryption */
                    ret = crypt.encrypt (handle_crypt, &input[0], input.size (), ciphertext);
                    if (errorcode_t::success != ret) {
                        __leave2_trace (ret);
                    }

                    /* Additional Authentication Tag
                     * concatenate AAD, IV, CT, AL
                     */
                    binary_t hmac_input;
                    hmac_input.insert (hmac_input.end (), aad.begin (), aad.end ());
                    hmac_input.insert (hmac_input.end (), iv.begin (), iv.end ());
                    hmac_input.insert (hmac_input.end (), ciphertext.begin (), ciphertext.end ());
                    hmac_input.insert (hmac_input.end (), (byte_t *) &al, (byte_t *) &al + sizeof (int64));

                    ret = hash.open (&handle_hash, (hash_algorithm_t) enc_hash_alg, &cek[0], cek_size / 2);
                    if (errorcode_t::success != ret) {
                        __leave2_trace (ret);
                    }
                    ret = hash.hash (handle_hash, &hmac_input[0], hmac_input.size (), tag);
                    if (errorcode_t::success != ret) {
                        __leave2_trace (ret);
                    }
                    tag.resize (tag.size () / 2);
                }
                __finally2
                {
                    hash.close (handle_hash);
                    crypt.close (handle_crypt);
                }
            } else if (jwe_type_t::jwe_type_aesgcm == enc_type) {
                crypt_context_t* handle_crypt = nullptr;
                crypt.open (&handle_crypt, (crypt_algorithm_t) enc_crypt_alg, (crypt_mode_t) enc_crypt_mode,
                            &cek[0], cek.size (), &iv[0], iv.size ());
                /* Content Encryption */
                ret = crypt.encrypt2 (handle_crypt, &input[0], input.size (), ciphertext, &aad, &tag);
                crypt.close (handle_crypt);
            }
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t json_object_encryption::decrypt (jose_context_t* context, jwe_t enc, jwa_t alg, binary_t input, binary_t& output)
{
    return decrypt (context, enc, alg, nullptr, input, output);
}

return_t json_object_encryption::decrypt (jose_context_t* context, jwe_t enc, jwa_t alg, const char* kid, binary_t input, binary_t& output)
{
    return_t ret = errorcode_t::success;
    jose_context_t* handle = static_cast <jose_context_t*> (context);
    openssl_crypt crypt;
    openssl_hash hash;
    crypto_advisor* advisor = crypto_advisor::get_instance ();

    __try2
    {
        if (nullptr == context) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace (ret);
        }

        jose_encryptions_map_t::iterator iter = handle->encryptions.find (enc);
        if (handle->encryptions.end () == iter) {
            ret = errorcode_t::internal_error;
            __leave2_trace (ret);
        }

        const hint_jose_encryption_t* alg_info = advisor->hintof_jose_algorithm (alg);      // key management
        const hint_jose_encryption_t* enc_info = advisor->hintof_jose_encryption (enc);     // content encryption

        jose_encryption_t& item = iter->second;
        binary_t cek;                                                                           // local, enc, from encrypted_key
        binary_t iv = item.datamap[crypt_item_t::item_iv];                                      // in, enc
        binary_t aad = item.datamap[crypt_item_t::item_aad];                                    // in, enc
        binary_t encrypted_key = item.recipients[alg].datamap[crypt_item_t::item_encryptedkey]; // in, alg
        binary_t tag = item.datamap[crypt_item_t::item_tag];                                    // in, enc
        binary_t ciphertext = item.datamap[crypt_item_t::item_ciphertext];                      // in, enc
        binary_t apu = item.recipients[alg].datamap[crypt_item_t::item_apu];
        binary_t apv = item.recipients[alg].datamap[crypt_item_t::item_apv];

        // alg part - encrypted_key from cek
        {
            const char* alg_name = alg_info->alg_name;
            crypt_mode2_t crypt_mode = (crypt_mode2_t) alg_info->mode;
            crypt_algorithm_t alg_crypt_alg = (crypt_algorithm_t) alg_info->crypt_alg;
            crypt_mode_t alg_crypt_mode = (crypt_mode_t) alg_info->crypt_mode;
            int alg_keysize = alg_info->keysize;
            hash_algorithm_t alg_hash_alg = (hash_algorithm_t) alg_info->hash_alg;

            binary_t oct;
            /* RFC3394 Advanced Encryption Standard (AES) Key Wrap Algorithm
             * 2.2.3.1 Default Initial Value
             * iv 0xa6 ...
             */
            binary_t kw_iv;
            kw_iv.resize (8);
            memset (&kw_iv[0], 0xa6, kw_iv.size ());

            EVP_PKEY* pkey = nullptr;
            if (kid) {
                pkey = handle->key->find (kid, alg, crypto_use_t::use_enc);
            } else {
                std::string kid_selected;
                pkey = handle->key->select (kid_selected, alg, crypto_use_t::use_enc);
            }

            if (nullptr == pkey) {
                ret = errorcode_t::not_found;
                __leave2_trace (ret);
            }
            ret = check_constraints (alg, pkey);
            if (errorcode_t::success != ret) {
                __leave2;
            }

            if (crypto_key_t::hmac_key == alg_info->kty) {

                /* EVP_KEY_HMAC key data and length */
                size_t key_length = 0;
                EVP_PKEY_get_raw_private_key ((EVP_PKEY *) pkey, nullptr, &key_length);
                oct.resize (key_length);
                EVP_PKEY_get_raw_private_key ((EVP_PKEY *) pkey, &oct [0], &key_length);
            }

            uint32 alg_type = CRYPT_ALG_TYPE (alg);
            if (jwa_type_t::jwa_type_rsa == alg_type) {
                /*
                 * RSA1_5, RSA-OAEP, RSA-OAEP-256
                 * RFC7518 4.2.  Key Encryption with RSAES-PKCS1-v1_5
                 * A key of size 2048 bits or larger MUST be used with this algorithm.
                 * RFC7518 4.3.  Key Encryption with RSAES OAEP
                 * A key of size 2048 bits or larger MUST be used with this algorithm.
                 * RFC7520 5.1. Key Encryption Using RSA v1.5 and AES-HMAC-SHA2
                 * RFC7520 5.2. Key Encryption Using RSA-OAEP with AES-GCM
                 */
                ret = crypt.decrypt (pkey, encrypted_key, cek, crypt_mode);
            } else if (jwa_type_t::jwa_type_aeskw == alg_type) {
                /*
                 * A128KW, A192KW, A256KW
                 * RFC7518 4.4. Key Wrapping with AES Key Wrap
                 * RFC7520 5.8. Key Wrap Using AES-KeyWrap with AES-GCM
                 */
                crypt_context_t* handle_kw = nullptr;
                crypt.open (&handle_kw, alg_crypt_alg, alg_crypt_mode, &oct[0], oct.size (), &kw_iv[0], kw_iv.size ());
                ret = crypt.decrypt (handle_kw, &encrypted_key[0], encrypted_key.size (), cek);
                crypt.close (handle_kw);
            } else if (jwa_type_t::jwa_type_dir == alg_type) {
                /*
                 * dir
                 * RFC7518 4.5. Direct Encryption with a Shared Symmetric Key
                 * RFC7520 5.6. Direct Encryption Using AES-GCM
                 */
                cek = oct;
            } else if (jwa_type_t::jwa_type_ecdh == alg_type) {
                /*
                 * ECDH-ES
                 * RFC7518 4.6. Key Agreement with Elliptic Curve Diffie-Hellman Ephemeral Static (ECDH-ES)
                 * 1.  directly as the Content Encryption Key (CEK) for the "enc"
                 *     algorithm, in the Direct Key Agreement mode, or
                 * RFC7520 5.5. Key Agreement Using ECDH-ES with AES-CBC-HMAC-SHA2
                 */
                EVP_PKEY* epk = item.recipients[alg].epk;
                int keylen = enc_info->keysize;
                uint32 enc_type = CRYPT_ENC_TYPE (enc);
                if (jwe_type_t::jwe_type_aescbc_hs == enc_type) {
                    keylen *= 2;
                }

                ret = ecdh_es (pkey, epk, enc_info->alg_name, "", "", keylen, cek);
            } else if (jwa_type_t::jwa_type_ecdh_aeskw == alg_type) {
                /*
                 * ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW
                 * RFC7518 4.6. Key Agreement with Elliptic Curve Diffie-Hellman Ephemeral Static (ECDH-ES)
                 * 2.  as a symmetric key used to wrap the CEK with the "A128KW",
                 *     "A192KW", or "A256KW" algorithms, in the Key Agreement with Key
                 *     Wrapping mode.
                 * RFC7520 5.4. Key Agreement with Key Wrapping Using ECDH-ES and AES-KeyWrap with AES-GCM
                 */
                binary_t derived_key;
                EVP_PKEY* epk = item.recipients[alg].epk;
                int keylen = alg_info->keysize;
                uint32 enc_type = CRYPT_ENC_TYPE (enc);
                if (jwe_type_t::jwe_type_aescbc_hs == enc_type) {
                    //keylen *= 2;
                }
                ret = ecdh_es (pkey, epk, alg_info->alg_name, "", "", keylen, derived_key);

                crypt_context_t* handle_kw = nullptr;
                crypt.open (&handle_kw, alg_crypt_alg, alg_crypt_mode, &derived_key[0], derived_key.size (), &kw_iv[0], kw_iv.size ());
                ret = crypt.decrypt (handle_kw, &encrypted_key[0], encrypted_key.size (), cek);
                crypt.close (handle_kw);
            } else if (jwa_type_t::jwa_type_aesgcmkw == alg_type) {
                /*
                 * A128GCMKW, A192GCMKW, A256GCMKW
                 * RFC7518 4.7. Key Encryption with AES GCM
                 * RFC7520 5.7. Key Wrap Using AES-GCM KeyWrap with AES-CBC-HMAC-SHA2
                 */
                binary_t iv1 = item.recipients[alg].datamap[crypt_item_t::item_iv];
                binary_t aad1; // empty
                binary_t tag1 = item.recipients[alg].datamap[crypt_item_t::item_tag];

                /* cek, aad(null), tag = AESGCM (HMAC.key, iv).decrypt (encryted_key) */
                crypt_context_t* handle_crypt = nullptr;
                crypt.open (&handle_crypt, alg_crypt_alg, alg_crypt_mode, &oct[0], oct.size (), &iv1[0], iv1.size ());
                ret = crypt.decrypt2 (handle_crypt, &encrypted_key[0], encrypted_key.size (), cek, &aad1, &tag1);
                crypt.close (handle_crypt);
            } else if (jwa_type_t::jwa_type_pbes_hs_aeskw == alg_type) {
                /*
                 * RFC7518 4.8. Key Encryption with PBES2
                 * PBES2-HS256+A128KW, PBES2-HS384+A192KW, PBES2-HS512+A256KW
                 * RFC7520 5.3. Key Wrap Using PBES2-AES-KeyWrap with AES-CBC-HMAC-SHA2
                 */
                binary_t p2s = item.recipients[alg].datamap[crypt_item_t::item_p2s];
                uint32 p2c = item.recipients[alg].p2c;

                const EVP_MD* alg_evp_md = (const EVP_MD*) advisor->find_evp_md (alg_hash_alg);
                binary_t salt;
                /* salt
                 * salt = UTF8(alg) + 0 + BASE64URL_DECODE(p2s)
                 */
                salt.insert (salt.end (), (byte_t*) alg_name, (byte_t*) alg_name + strlen (alg_name));
                salt.insert (salt.end (), 0);
                salt.insert (salt.end (), p2s.begin (), p2s.end ());

                /* key derivation
                 * derived_key = PKCS5_PBKDF2_HMAC(passphrase, salt, iteration_count = p2c, hash)
                 */
                binary_t pbkdf2_derived_key;
                pbkdf2_derived_key.resize (alg_keysize);
                PKCS5_PBKDF2_HMAC ((char *) &oct[0], oct.size (), &salt[0], salt.size (), p2c, alg_evp_md,
                                   pbkdf2_derived_key.size (), &pbkdf2_derived_key[0]);

                crypt_context_t* crypt_handle = nullptr;
                crypt.open (&crypt_handle, alg_crypt_alg, alg_crypt_mode,
                            &pbkdf2_derived_key[0], pbkdf2_derived_key.size (), &kw_iv[0], kw_iv.size ());
                ret = crypt.decrypt (crypt_handle, &encrypted_key[0], encrypted_key.size (), cek);
                crypt.close (crypt_handle);
            }
        }

        if (errorcode_t::success != ret) {
            __leave2_trace (ret);
        }

        // enc part - ciphertext using cek, iv
        {
            crypt_algorithm_t enc_crypt_alg = (crypt_algorithm_t) enc_info->crypt_alg;
            crypt_mode_t enc_crypt_mode = (crypt_mode_t) enc_info->crypt_mode;
            hash_algorithm_t enc_hash_alg = (hash_algorithm_t) enc_info->hash_alg;

            uint32 enc_type = CRYPT_ENC_TYPE (enc);
            if (jwe_type_t::jwe_type_aescbc_hs == enc_type) {
                int cek_size = cek.size ();
                int64 aad_length = aad.size () * 8;
                int64 al = htonll (aad_length);

                crypt_context_t* handle_crypt = nullptr;
                hash_context_t* handle_hash = nullptr;
                __try2 {
                    /* Additional Authentication Tag
                     * concatenate AAD, IV, CT, AL
                     */
                    binary_t hmac_input;
                    binary_t tag1;
                    hmac_input.insert (hmac_input.end (), aad.begin (), aad.end ());
                    hmac_input.insert (hmac_input.end (), iv.begin (), iv.end ());
                    hmac_input.insert (hmac_input.end (), ciphertext.begin (), ciphertext.end ());
                    hmac_input.insert (hmac_input.end (), (byte_t *) &al, (byte_t *) &al + sizeof (int64));

                    ret = hash.open (&handle_hash, (hash_algorithm_t) enc_hash_alg, &cek[0], cek_size / 2);
                    if (errorcode_t::success != ret) {
                        __leave2_trace (ret);
                    }
                    ret = hash.hash (handle_hash, &hmac_input[0], hmac_input.size (), tag1);
                    if (errorcode_t::success != ret) {
                        __leave2_trace (ret);
                    }
                    tag1.resize (tag1.size () / 2);

                    if (tag1 != tag) {
                        ret = errorcode_t::mismatch;
                        __leave2_trace (ret);
                    }

                    ret = crypt.open (&handle_crypt, (crypt_algorithm_t) enc_crypt_alg, (crypt_mode_t) enc_crypt_mode,
                                      &cek[0] + (cek_size / 2), cek_size / 2, &iv[0], iv.size ());
                    if (errorcode_t::success != ret) {
                        __leave2_trace (ret);
                    }

                    /* Content Encryption */
                    ret = crypt.decrypt (handle_crypt, &ciphertext[0], ciphertext.size (), output);
                    if (errorcode_t::success != ret) {
                        __leave2_trace (ret);
                    }
                }
                __finally2
                {
                    if (handle_hash) {
                        hash.close (handle_hash);
                    }
                    if (handle_crypt) {
                        crypt.close (handle_crypt);
                    }
                }
            } else if (jwe_type_t::jwe_type_aesgcm == enc_type) {
                crypt_context_t* handle_crypt = nullptr;
                crypt.open (&handle_crypt, (crypt_algorithm_t) enc_crypt_alg, (crypt_mode_t) enc_crypt_mode,
                            &cek[0], cek.size (), &iv[0], iv.size ());
                /* Content Encryption */
                ret = crypt.decrypt2 (handle_crypt, &ciphertext[0], ciphertext.size (), output, &aad, &tag);
                crypt.close (handle_crypt);
            }
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t json_object_encryption::check_constraints (jwa_t alg, EVP_PKEY* pkey)
{
    return_t ret = errorcode_t::success;

    //int alg_type = CRYPT_ALG_TYPE (alg);
    __try2
    {
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
            case jwa_t::jwa_rsa_oaep_256:
            {
                int bits = EVP_PKEY_bits ((EVP_PKEY*) pkey);
                if (bits < 2048) {
                    ret = errorcode_t::low_security;
                    __leave2_trace (ret);
                }
            }
            break;
            default:
                break;
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

}
}  // namespace
