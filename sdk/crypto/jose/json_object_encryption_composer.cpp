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

#include <hotplace/sdk/base/basic/binary.hpp>
#include <hotplace/sdk/base/string/string.hpp>
#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/crypto_keychain.hpp>
#include <hotplace/sdk/crypto/basic/evp_key.hpp>
#include <hotplace/sdk/crypto/basic/openssl_crypt.hpp>
#include <hotplace/sdk/crypto/basic/openssl_ecdh.hpp>
#include <hotplace/sdk/crypto/basic/openssl_hash.hpp>
#include <hotplace/sdk/crypto/basic/openssl_kdf.hpp>
#include <hotplace/sdk/crypto/basic/openssl_prng.hpp>
#include <hotplace/sdk/crypto/jose/json_object_encryption.hpp>
#include <hotplace/sdk/crypto/jose/json_object_signing.hpp>
#include <hotplace/sdk/crypto/jose/json_object_signing_encryption.hpp>
#include <hotplace/sdk/crypto/jose/json_web_key.hpp>
#include <hotplace/sdk/io/basic/json.hpp>
#include <hotplace/sdk/io/basic/zlib.hpp>

namespace hotplace {
namespace crypto {

json_object_encryption::composer::composer() {}

return_t json_object_encryption::composer::compose_encryption(jose_context_t *handle, std::string &output, jose_serialization_t type) {
    return_t ret = errorcode_t::success;
    crypto_advisor *advisor = crypto_advisor::get_instance();

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
        jose_encryption_t &encryption = eit->second;
        if (encryption.recipients.empty()) {
            __leave2;
        }

        jose_recipients_t::iterator rit = encryption.recipients.begin();
        jose_recipient_t &recipient = rit->second;

        std::string b64_header;
        std::string b64_iv;
        std::string b64_tag;
        std::string b64_ciphertext;
        std::string b64_encryptedkey;

        const auto &member_iv = encryption.datamap[crypt_item_t::item_iv];
        const auto &member_tag = encryption.datamap[crypt_item_t::item_tag];
        const auto &member_ciphertext = encryption.datamap[crypt_item_t::item_ciphertext];

        base64_encode((byte_t *)encryption.header.c_str(), encryption.header.size(), b64_header, encoding_t::encoding_base64url);
        base64_encode(member_iv.empty() ? nullptr : &member_iv[0], member_iv.size(), b64_iv, encoding_t::encoding_base64url);
        base64_encode(member_tag.empty() ? nullptr : &member_tag[0], member_tag.size(), b64_tag, encoding_t::encoding_base64url);
        base64_encode(member_ciphertext.empty() ? nullptr : &member_ciphertext[0], member_ciphertext.size(), b64_ciphertext, encoding_t::encoding_base64url);

        if (jose_serialization_t::jose_compact == type) {
            const auto member_encryptedkey = recipient.datamap[crypt_item_t::item_encryptedkey];
            base64_encode(member_encryptedkey.empty() ? nullptr : &member_encryptedkey[0], member_encryptedkey.size(), b64_encryptedkey,
                          encoding_t::encoding_base64url);

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
            const auto member_encryptedkey = recipient.datamap[crypt_item_t::item_encryptedkey];
            base64_encode(member_encryptedkey.empty() ? nullptr : &member_encryptedkey[0], member_encryptedkey.size(), b64_encryptedkey,
                          encoding_t::encoding_base64url);

            json_t *json_serialization = nullptr;
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

                char *contents = json_dumps(json_serialization, JOSE_JSON_FORMAT);
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
            json_t *json_serialization = nullptr;
            json_t *json_recipients = nullptr;
            json_t *json_recipient = nullptr;
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
                for (auto &pair : encryption.recipients) {
                    const jwa_t &alg = pair.first;
                    jose_recipient_t &recipient = pair.second;

                    json_recipient = json_object();
                    if (json_recipient) {
                        json_t *header = json_object();
                        if (header) {
                            const hint_jose_encryption_t *hint = advisor->hintof_jose_algorithm(alg);
                            json_object_set_new(header, "alg", json_string(hint->alg_name));
                            if (recipient.kid.size()) {
                                json_object_set_new(header, "kid", json_string(recipient.kid.c_str()));
                            }

                            uint32 alg_group = hint->group;
                            if ((jwa_group_t::jwa_group_ecdh == alg_group) || (jwa_group_t::jwa_group_ecdh_aeskw == alg_group)) {
                                binary_t pub1;
                                binary_t pub2;
                                const EVP_PKEY *epk = recipient.epk;
                                crypto_key::get_public_key(epk, pub1, pub2);
                                json_t *json_epk = json_object();
                                if (json_epk) {
                                    std::string kty;
                                    std::string curve_name;
                                    advisor->ktyof_ec_curve(epk, kty);
                                    advisor->nameof_ec_curve(epk, curve_name);

                                    json_object_set_new(json_epk, "kty", json_string(kty.c_str()));
                                    json_object_set_new(json_epk, "crv", json_string(curve_name.c_str()));
                                    json_object_set_new(
                                        json_epk, "x",
                                        json_string(base64_encode(pub1.empty() ? nullptr : &pub1[0], pub1.size(), encoding_t::encoding_base64url).c_str()));
                                    if (pub2.size()) {
                                        json_object_set_new(
                                            json_epk, "y",
                                            json_string(base64_encode(pub2.empty() ? nullptr : &pub2[0], pub2.size(), encoding_t::encoding_base64url).c_str()));
                                    }
                                    json_object_set_new(header, "epk", json_epk);
                                }
                            } else if (jwa_group_t::jwa_group_aesgcmkw == alg_group) {
                                std::string b64_iv;
                                std::string b64_tag;
                                const auto &member_iv = recipient.datamap[crypt_item_t::item_iv];
                                const auto &member_tag = recipient.datamap[crypt_item_t::item_tag];
                                base64_encode(member_iv.empty() ? nullptr : &member_iv[0], member_iv.size(), b64_iv, encoding_t::encoding_base64url);
                                base64_encode(member_tag.empty() ? nullptr : &member_tag[0], member_tag.size(), b64_tag, encoding_t::encoding_base64url);
                                json_object_set_new(header, "iv", json_string(b64_iv.c_str()));
                                json_object_set_new(header, "tag", json_string(b64_tag.c_str()));
                            } else if (jwa_group_t::jwa_group_pbes_hs_aeskw == alg_group) {
                                std::string b64_p2s;
                                const auto &member_p2s = recipient.datamap[crypt_item_t::item_p2s];
                                base64_encode(member_p2s.empty() ? nullptr : &member_p2s[0], member_p2s.size(), b64_p2s, encoding_t::encoding_base64url);
                                json_object_set_new(header, "p2s", json_string(b64_p2s.c_str()));
                                json_object_set_new(header, "p2c", json_integer(recipient.p2c));
                            }

                            json_object_set_new(json_recipient, "header", header);
                        }

                        const auto &member_encryptedkey = recipient.datamap[crypt_item_t::item_encryptedkey];
                        base64_encode(member_encryptedkey.empty() ? nullptr : &member_encryptedkey[0], member_encryptedkey.size(), b64_encryptedkey,
                                      encoding_t::encoding_base64url);
                        json_object_set_new(json_recipient, "encrypted_key", json_string(b64_encryptedkey.c_str()));

                        json_array_append_new(json_recipients, json_recipient);
                    }
                }
                json_object_set_new(json_serialization, "recipients", json_recipients);
                json_object_set_new(json_serialization, "iv", json_string(b64_iv.c_str()));
                json_object_set_new(json_serialization, "ciphertext", json_string(b64_ciphertext.c_str()));
                json_object_set_new(json_serialization, "tag", json_string(b64_tag.c_str()));

                char *contents = json_dumps(json_serialization, JOSE_JSON_FORMAT);
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
    __finally2 {}
    return ret;
}

return_t json_object_encryption::composer::compose_encryption_aead_header(const std::string &source_encoded, const binary_t &tag, binary_t &aad,
                                                                          std::string &output_encoded) {
    return_t ret = errorcode_t::success;
    json_t *json_header = nullptr;

    output_encoded.clear();

    /* compact, flattened */
    // protected_header
    json_open_stream(&json_header, source_encoded.c_str(), true);
    if (json_header) {
        const char *alg_value = nullptr;
        const char *tag_value = nullptr;
        json_unpack(json_header, "{s:s}", "alg", &alg_value);
        json_unpack(json_header, "{s:s}", "tag", &tag_value);
        if (alg_value) {
            if ((nullptr == tag_value) || (tag_value && (0 == strlen(tag_value)))) {
                std::string tag_encoded;
                base64_encode(tag.empty() ? nullptr : &tag[0], tag.size(), tag_encoded, encoding_t::encoding_base64url);

                json_object_set_new(json_header, "tag", json_string(tag_encoded.c_str()));
                char *contents = json_dumps(json_header, JOSE_JSON_FORMAT);
                if (nullptr != contents) {
                    std::string header = contents;
                    base64_encode((byte_t *)header.c_str(), header.size(), aad,
                                  encoding_t::encoding_base64url);  // update for encryption
                    output_encoded = std::move(header);             // update for JWE.output
                    free(contents);
                }
            }
        }
        json_decref(json_header);
    }
    return ret;
}

return_t json_object_encryption::composer::compose_encryption_dorandom(jose_context_t *handle, jwe_t enc, std::list<jwa_t> const &algs) {
    return_t ret = errorcode_t::success;
    openssl_prng rand;
    crypto_advisor *advisor = crypto_advisor::get_instance();

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
            const hint_jose_encryption_t *enc_hint = advisor->hintof_jose_encryption(enc);  // content encryption
            if (nullptr == enc_hint) {
                ret = errorcode_t::not_supported;
                __leave2;
            }

            const EVP_CIPHER *enc_evp_cipher = advisor->find_evp_cipher(enc_hint->crypt_alg, enc_hint->crypt_mode);
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

                // const hint_jose_encryption_t* alg_hint =
                // advisor->hintof_jose_algorithm (alg);  // key management
                std::string kid;
                const EVP_PKEY *pkey = handle->key->select(kid, alg, crypto_use_t::use_enc);
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

                item.header.assign(protected_header.empty() ? nullptr : (char *)&protected_header[0], protected_header.size());
                base64_encode(protected_header.empty() ? nullptr : &protected_header[0], protected_header.size(), item.datamap[crypt_item_t::item_aad],
                              encoding_t::encoding_base64url);

                recipient.header = std::string(header.empty() ? nullptr : (char *)&header[0], header.size());
                recipient.kid = kid;
                item.recipients.insert(std::make_pair(alg, recipient));
            } else if (algs.size() > 1) {
                docompose_protected_header(protected_header, enc, jwa_t::jwa_unknown, jose_compose_t::jose_enc_only, "", handle->flags);
                item.header.assign(protected_header.empty() ? nullptr : (char *)&protected_header[0], protected_header.size());
                base64_encode(protected_header.empty() ? nullptr : &protected_header[0], protected_header.size(), item.datamap[crypt_item_t::item_aad],
                              encoding_t::encoding_base64url);

                for (const jwa_t &alg : algs) {
                    // const hint_jose_encryption_t* alg_hint =
                    // advisor->hintof_jose_algorithm (alg);  // key management
                    std::string kid;
                    const EVP_PKEY *pkey = handle->key->select(kid, alg, crypto_use_t::use_enc);

                    crypt_datamap_t datamap;
                    crypt_variantmap_t variantmap;
                    jose_recipient_t recipient;

                    recipient.kid = kid;
                    docompose_encryption_recipient_random(alg, pkey, recipient, datamap, variantmap);

                    binary_t header;
                    docompose_encryption_header_parameter(header, jwe_t::jwe_unknown, alg, jose_compose_t::jose_alg_only, kid, datamap, variantmap);
                    recipient.header = std::string(header.empty() ? nullptr : (char *)&header[0], header.size());
                    item.recipients.insert(std::make_pair(alg, recipient));
                }
            }

            handle->protected_header = protected_header;
            handle->encryptions.insert(std::make_pair(enc, item));
        }
    }
    __finally2 {}
    return ret;
}

return_t json_object_encryption::composer::docompose_protected_header(binary_t &header, jwe_t enc, jwa_t alg, jose_compose_t flag, const std::string &kid,
                                                                      uint32 flags) {
    return_t ret = errorcode_t::success;
    crypt_datamap_t datamap;
    crypt_variantmap_t variantmap;

    ret = docompose_encryption_header_parameter(header, enc, alg, flag, kid, datamap, variantmap, flags);
    return ret;
}

return_t json_object_encryption::composer::docompose_encryption_header_parameter(binary_t &header, jwe_t enc, jwa_t alg, jose_compose_t flag,
                                                                                 const std::string &kid, crypt_datamap_t &datamap,
                                                                                 crypt_variantmap_t &variantmap, uint32 flags) {
    return_t ret = errorcode_t::success;
    json_t *json_header = nullptr;
    crypto_advisor *advisor = crypto_advisor::get_instance();

    __try2 {
        header.clear();

        if (0 == (jose_compose_t::jose_enc_alg & flag)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const char *enc_value = advisor->nameof_jose_encryption(enc);
        const char *alg_value = advisor->nameof_jose_algorithm(alg);

        json_header = json_object();

        if (jose_compose_t::jose_enc_only & flag) {
            if (nullptr == enc_value) {
                ret = errorcode_t::invalid_parameter;
                __leave2;
            }
            json_object_set_new(json_header, "enc", json_string(enc_value));
        }
        if (jose_compose_t::jose_alg_only & flag) {
            const hint_jose_encryption_t *alg_hint = advisor->hintof_jose_algorithm(alg);
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
                const EVP_PKEY *epk = (const EVP_PKEY *)variantmap[crypt_item_t::item_epk].data.p;
                crypto_key::get_public_key(epk, pub1, pub2);
                json_t *json_epk = json_object();
                if (json_epk) {
                    std::string kty;
                    std::string curve_name;
                    advisor->ktyof_ec_curve(epk, kty);
                    advisor->nameof_ec_curve(epk, curve_name);

                    json_object_set_new(json_epk, "kty", json_string(kty.c_str()));
                    json_object_set_new(json_epk, "crv", json_string(curve_name.c_str()));
                    json_object_set_new(json_epk, "x",
                                        json_string(base64_encode(pub1.empty() ? nullptr : &pub1[0], pub1.size(), encoding_t::encoding_base64url).c_str()));
                    if (pub2.size()) {
                        json_object_set_new(json_epk, "y",
                                            json_string(base64_encode(pub2.empty() ? nullptr : &pub2[0], pub2.size(), encoding_t::encoding_base64url).c_str()));
                    }
                    json_object_set_new(json_header, "epk", json_epk);
                }
            } else if (jwa_group_t::jwa_group_aesgcmkw == alg_group) {
                // iv, tag
                binary_t iv1 = datamap[crypt_item_t::item_iv];
                binary_t tag1 = datamap[crypt_item_t::item_tag];
                json_object_set_new(json_header, "iv",
                                    json_string(base64_encode(iv1.empty() ? nullptr : &iv1[0], iv1.size(), encoding_t::encoding_base64url).c_str()));
                json_object_set_new(json_header, "tag",
                                    json_string(base64_encode(tag1.empty() ? nullptr : &tag1[0], tag1.size(), encoding_t::encoding_base64url).c_str()));
            } else if (jwa_group_t::jwa_group_pbes_hs_aeskw == alg_group) {
                // p2s, p2c
                binary_t p2s = datamap[crypt_item_t::item_p2s];
                uint32 p2c = variantmap[crypt_item_t::item_p2c].data.i32;
                json_object_set_new(json_header, "p2s",
                                    json_string(base64_encode(p2s.empty() ? nullptr : &p2s[0], p2s.size(), encoding_t::encoding_base64url).c_str()));
                json_object_set_new(json_header, "p2c", json_integer(p2c));
            }
        }
        if (flags & jose_flag_t::jose_deflate) {
            // RFC 7520 5.9.  Compressed Content
            json_object_set_new(json_header, "zip", json_string("DEF"));
        }

        char *contents = json_dumps(json_header, JOSE_JSON_FORMAT);
        if (nullptr != contents) {
            header.insert(header.end(), (byte_t *)contents, (byte_t *)contents + strlen(contents));
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

return_t json_object_encryption::composer::docompose_encryption_recipient_random(jwa_t alg, const EVP_PKEY *pkey, jose_recipient_t &recipient,
                                                                                 crypt_datamap_t &datamap, crypt_variantmap_t &variantmap) {
    return_t ret = errorcode_t::success;
    crypto_advisor *advisor = crypto_advisor::get_instance();

    const hint_jose_encryption_t *alg_hint = advisor->hintof_jose_algorithm(alg);  // key management
    uint32 alg_group = alg_hint->group;

    recipient.alg_info = alg_hint;

    if ((jwa_group_t::jwa_group_ecdh == alg_group) || (jwa_group_t::jwa_group_ecdh_aeskw == alg_group)) {
        // epk
        uint32 nid = 0;
        crypto_key key;
        crypto_keychain keyset;
        std::string kid;
        nidof_evp_pkey(pkey, nid);                                // "crv" of key
        keyset.add_ec2(&key, nid, keydesc());                     // same "crv"
        recipient.epk = key.select(crypto_use_t::use_enc, true);  // EVP_PKEY_up_ref
        variant vt;
        vt.set_pointer(recipient.epk);
        variantmap[crypt_item_t::item_epk] = vt.content();
    } else if (jwa_group_t::jwa_group_aesgcmkw == alg_group) {
        // iv, tag
        const EVP_CIPHER *alg_evp_cipher = advisor->find_evp_cipher(alg_hint->crypt_alg, alg_hint->crypt_mode);
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
        variant vt;
        vt.set_int32(recipient.p2c);
        datamap[crypt_item_t::item_p2s] = recipient.datamap[crypt_item_t::item_p2s];
        variantmap[crypt_item_t::item_p2c] = vt.content();
    }
    return ret;
}

static void json_unpack_helper(std::list<json_t *> const &pool, const char *key, const char **ptr) {
    const char *value = nullptr;
    int ret = 0;

    __try2 {
        if (nullptr == key || nullptr == ptr) {
            __leave2;
        }

        for (json_t *json : pool) {
            ret = json_unpack(json, "{s:s}", key, &value);
            if (0 == ret) {
                *ptr = value;
                break;
            }
        }
    }
    __finally2 {}
}

static void json_unpack_helper(std::list<json_t *> const &pool, const char *key, int *ptr) {
    int value = 0;
    int ret = 0;

    __try2 {
        if (nullptr == key || nullptr == ptr) {
            __leave2;
        }

        for (json_t *json : pool) {
            ret = json_unpack(json, "{s:i}", key, &value);
            if (0 == ret) {
                *ptr = value;
                break;
            }
        }
    }
    __finally2 {}
}

static void json_unpack_helper(std::list<json_t *> const &pool, const char *key, json_t **ptr) {
    json_t *value = nullptr;
    int ret = 0;

    __try2 {
        if (nullptr == key || nullptr == ptr) {
            __leave2;
        }

        for (json_t *json : pool) {
            ret = json_unpack(json, "{s:o}", key, &value);
            if (0 == ret) {
                *ptr = value;
                break;
            }
        }
    }
    __finally2 {}
}

return_t json_object_encryption::composer::parse_decryption(jose_context_t *handle, const char *input) {
    return_t ret = errorcode_t::success;
    json_t *json_root = nullptr;
    split_context_t *split_handle = nullptr;

    __try2 {
        if (nullptr == handle || nullptr == input) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        return_t ret_test = json_open_stream(&json_root, input, true);
        if (errorcode_t::success == ret_test) {
            jose_encryption_t item;

            json_t *json_recipients = nullptr;
            json_unpack(json_root, "{s:o}", "recipients", &json_recipients);

            if (json_recipients) {  // jose_serialization_t::jose_json
                if (json_is_array(json_recipients)) {
                    const char *protected_header = nullptr;
                    const char *iv = nullptr;
                    const char *ciphertext = nullptr;
                    const char *tag = nullptr;

                    json_unpack(json_root, "{s:s}", "protected", &protected_header);
                    json_unpack(json_root, "{s:s,s:s,s:s}", "iv", &iv, "ciphertext", &ciphertext, "tag", &tag);

                    jwe_t enc_type = jwe_t::jwe_unknown;
                    doparse_decryption(handle, protected_header, nullptr, iv, ciphertext, tag, json_root, enc_type, item);

                    size_t array_size = json_array_size(json_recipients);
                    for (size_t index = 0; index < array_size; index++) {
                        json_t *json_recipient = json_array_get(json_recipients, index);
                        json_t *json_header = nullptr;
                        jose_recipient_t recipient;
                        jwa_t alg_type = jwa_t::jwa_unknown;

                        const char *encrypted_key = nullptr;
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
                const char *protected_header = nullptr;
                const char *encrypted_key = nullptr;
                const char *iv = nullptr;
                const char *ciphertext = nullptr;
                const char *tag = nullptr;

                json_unpack(json_root, "{s:s}", "protected", &protected_header);
                json_unpack(json_root, "{s:s,s:s,s:s}", "iv", &iv, "ciphertext", &ciphertext, "tag", &tag);
                json_unpack(json_root, "{s:s}", "encrypted_key",
                            &encrypted_key);  // not exist in case of "dir", "ECDH-ES"

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

return_t json_object_encryption::composer::doparse_decryption(jose_context_t *handle, const char *protected_header, const char *encrypted_key, const char *iv,
                                                              const char *ciphertext, const char *tag, void *json_t_root, jwe_t &type,
                                                              jose_encryption_t &item) {
    return_t ret = errorcode_t::success;
    json_t *json_protected = nullptr;
    crypto_advisor *advisor = crypto_advisor::get_instance();
    json_t *json_root = (json_t *)json_t_root;
    std::list<json_t *> pool;

    __try2 {
        type = jwe_t::jwe_unknown;

        // protected can be nullptr
        // see RFC 7520 5.12.  Protecting Content Only
        std::string protected_header_decoded;
        const char *enc = nullptr;
        if (protected_header) {
            protected_header_decoded = std::move(base64_decode_careful(protected_header, strlen(protected_header), encoding_t::encoding_base64url));
            ret = json_open_stream(&json_protected, protected_header_decoded.c_str(), true);
            if (errorcode_t::success != ret) {
                __leave2;
            }

            pool.push_back(json_protected);
        }

        if (json_root) {
            // RFC 7520 5.10.  Including Additional Authenticated Data
            // only the flattened JWE JSON Serialization and general JWE JSON
            // Serialization are possible. check - test failed !!
            const char *aad = nullptr;
            json_unpack(json_root, "{s:s}", "aad", &aad);
            if (aad) {
                // Concatenation of the JWE Protected Header ".", and the base64url
                // [RFC4648] encoding of AAD as authenticated data
                binary_t bin_aad;
                bin_aad.insert(bin_aad.end(), protected_header, protected_header + strlen(protected_header));
                bin_aad.insert(bin_aad.end(), '.');
                bin_aad.insert(bin_aad.end(), aad, aad + strlen(aad));
                item.datamap[crypt_item_t::item_aad] = bin_aad;
            }

            // RFC 7520 5.12.  Protecting Content Only
            // only the general JWE JSON Serialization and flattened JWE JSON
            // Serialization are possible.
            json_t *unprotected_header = nullptr;
            json_unpack(json_root, "{s:o}", "unprotected", &unprotected_header);
            if (unprotected_header) {
                pool.push_back(unprotected_header);
            }
        }

        json_unpack_helper(pool, "enc", &enc);

        const hint_jose_encryption_t *enc_hint = advisor->hintof_jose_encryption(enc);
        if (nullptr == enc_hint) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        type = (jwe_t)enc_hint->type;
        item.enc_info = enc_hint;

        // do not update if crypt_item_t::item_aad already exists
        // see RFC 7520 5.10.  Including Additional Authenticated Data
        if (protected_header) {
            item.datamap.insert(std::make_pair(crypt_item_t::item_aad, std::move(str2bin(protected_header))));
        }

        item.header = std::move(protected_header_decoded);
        base64_decode(iv, strlen(iv), item.datamap[crypt_item_t::item_iv], encoding_t::encoding_base64url);
        base64_decode(tag, strlen(tag), item.datamap[crypt_item_t::item_tag], encoding_t::encoding_base64url);
        base64_decode(ciphertext, strlen(ciphertext), item.datamap[crypt_item_t::item_ciphertext], encoding_t::encoding_base64url);

        const char *zip = nullptr;
        json_unpack_helper(pool, "zip", &zip);
        if (zip) {
            // RFC 7520 5.9.  Compressed Content
            item.datamap[crypt_item_t::item_zip] = std::move(str2bin(zip));
        }
    }
    __finally2 {
        if (json_protected) {
            json_decref(json_protected);
        }
    }
    return ret;
}

return_t json_object_encryption::composer::doparse_decryption_recipient(jose_context_t *handle, const char *protected_header, const char *encrypted_key,
                                                                        void *json_t_root, void *json_t_recipient_header, jwa_t &type,
                                                                        jose_recipient_t &recipient) {
    return_t ret = errorcode_t::success;
    crypto_advisor *advisor = crypto_advisor::get_instance();
    std::list<json_t *> pool;

    json_t *json_root = (json_t *)json_t_root;
    json_t *json_recipient_header = (json_t *)json_t_recipient_header;
    json_t *json_protected = nullptr;

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
            std::string protected_header_decoded = std::move(base64_decode_careful(protected_header, strlen(protected_header), encoding_t::encoding_base64url));
            ret_test = json_open_stream(&json_protected, protected_header_decoded.c_str(), true);
            if (errorcode_t::success != ret_test) {
                ret = errorcode_t::bad_data;
                __leave2;
            }
            pool.push_back(json_protected);
        }
        if (json_root) {
            // RFC 7520 5.12.  Protecting Content Only
            // only the general JWE JSON Serialization and flattened JWE JSON
            // Serialization are possible.
            json_t *unprotected_header = nullptr;
            json_unpack(json_root, "{s:o}", "unprotected", &unprotected_header);
            if (unprotected_header) {
                pool.push_back(unprotected_header);
            }
        }

        const char *enc = nullptr;
        json_unpack_helper(pool, "enc", &enc);

        const hint_jose_encryption_t *enc_hint = advisor->hintof_jose_encryption(enc);
        if (nullptr == enc_hint) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        const char *enckey = nullptr;
        if (encrypted_key) {
            enckey = encrypted_key;
        } else {
            json_unpack_helper(pool, "encrypted_key", &enckey);
        }
        if (enckey) {
            base64_decode(enckey, strlen(enckey), recipient.datamap[crypt_item_t::item_encryptedkey], encoding_t::encoding_base64url);
        }

        const char *alg = nullptr;
        const char *kid = nullptr;
        json_unpack_helper(pool, "alg", &alg);
        json_unpack_helper(pool, "kid", &kid);
        const hint_jose_encryption_t *alg_hint = advisor->hintof_jose_algorithm(alg);
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
            json_t *epk = nullptr;
            const char *apu_value = nullptr;
            const char *apv_value = nullptr;
            json_unpack_helper(pool, "epk", &epk);
            json_unpack_helper(pool, "apu", &apu_value);
            json_unpack_helper(pool, "apv", &apv_value);

            const char *kty_value = nullptr;
            const char *crv_value = nullptr;
            const char *x_value = nullptr;
            const char *y_value = nullptr;

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
            jwk.add_ec_b64u(&key, crv_value, x_value, y_value, nullptr, keydesc());
            recipient.epk = key.select(crypto_use_t::use_enc, true);  // EVP_PKEY_up_ref
            if (apu_value) {
                base64_decode(apu_value, strlen(apu_value), recipient.datamap[crypt_item_t::item_apu], encoding_t::encoding_base64url);
            }
            if (apv_value) {
                base64_decode(apv_value, strlen(apv_value), recipient.datamap[crypt_item_t::item_apv], encoding_t::encoding_base64url);
            }
        } else if (jwa_group_t::jwa_group_aesgcmkw == alg_group) {  // iv, tag
            const char *iv_value = nullptr;
            const char *tag_value = nullptr;
            json_unpack_helper(pool, "iv", &iv_value);
            json_unpack_helper(pool, "tag", &tag_value);

            if (nullptr == iv_value || nullptr == tag_value) {
                ret = errorcode_t::bad_data;
                __leave2;
            }

            base64_decode(iv_value, strlen(iv_value), recipient.datamap[crypt_item_t::item_iv], encoding_t::encoding_base64url);
            base64_decode(tag_value, strlen(tag_value), recipient.datamap[crypt_item_t::item_tag], encoding_t::encoding_base64url);
        } else if (jwa_group_t::jwa_group_pbes_hs_aeskw == alg_group) {  // p2s, p2c
            const char *p2s = nullptr;
            int p2c = -1;
            json_unpack_helper(pool, "p2s", &p2s);
            json_unpack_helper(pool, "p2c", &p2c);

            if (nullptr == p2s || -1 == p2c) {
                ret = errorcode_t::bad_data;
                __leave2;
            }

            base64_decode(p2s, strlen(p2s), recipient.datamap[crypt_item_t::item_p2s], encoding_t::encoding_base64url);
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
