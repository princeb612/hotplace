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

#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/crypto_keychain.hpp>
#include <sdk/crypto/basic/openssl_crypt.hpp>
#include <sdk/crypto/basic/openssl_ecdh.hpp>
#include <sdk/crypto/basic/openssl_hash.hpp>
#include <sdk/crypto/basic/openssl_kdf.hpp>
#include <sdk/crypto/cose/cbor_object_encryption.hpp>
#include <sdk/crypto/cose/cbor_object_signing.hpp>
#include <sdk/crypto/cose/cbor_object_signing_encryption.hpp>
#include <sdk/crypto/cose/cose_composer.hpp>
#include <sdk/io/cbor/cbor_array.hpp>
#include <sdk/io/cbor/cbor_data.hpp>
#include <sdk/io/cbor/cbor_encode.hpp>
#include <sdk/io/cbor/cbor_map.hpp>
#include <sdk/io/cbor/cbor_publisher.hpp>
#include <sdk/io/cbor/cbor_reader.hpp>
#include <sdk/io/cbor/concise_binary_object_representation.hpp>
#include <set>

namespace hotplace {
using namespace io;
namespace crypto {

cbor_object_signing_encryption::cbor_object_signing_encryption() {
    // do nothing
}

cbor_object_signing_encryption::~cbor_object_signing_encryption() {
    // do nothing
}

return_t cbor_object_signing_encryption::open(cose_context_t** handle) {
    return_t ret = errorcode_t::success;
    cose_context_t* context = nullptr;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        __try_new_catch(context, new cose_context_t, ret, __leave2);
        *handle = context;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::close(cose_context_t* handle) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        clear_context(handle);
        delete handle;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::set(cose_context_t* handle, uint32 flags, uint32 debug_flags) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        handle->flags = flags;
        handle->debug_flags = debug_flags;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::get(cose_context_t* handle, uint32& flags, uint32& debug_flags) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        flags = handle->flags;
        debug_flags = handle->debug_flags;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::set(cose_context_t* handle, cose_param_t id, binary_t const& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        switch (id) {
            case cose_param_t::cose_external:
            case cose_param_t::cose_unsent_apu_id:
            case cose_param_t::cose_unsent_apu_nonce:
            case cose_param_t::cose_unsent_apu_other:
            case cose_param_t::cose_unsent_apv_id:
            case cose_param_t::cose_unsent_apv_nonce:
            case cose_param_t::cose_unsent_apv_other:
            case cose_param_t::cose_unsent_pub_other:
            case cose_param_t::cose_unsent_priv_other:
            case cose_param_t::cose_unsent_iv:
            case cose_param_t::cose_unsent_alg:
            case cose_param_t::cose_param_cek:
                handle->binarymap[id] = bin;
                break;
            default:
                ret = errorcode_t::request;
                break;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

#if 0
return_t cbor_object_signing_encryption::encrypt(cose_context_t* handle, crypto_key* key, cose_alg_t method, binary_t const& input, binary_t& output) {
    return_t ret = errorcode_t::success;
    cbor_object_encryption cose_encryption;

    ret = cose_encryption.encrypt(handle, key, method, input, output);
    return ret;
}

return_t cbor_object_signing_encryption::encrypt(cose_context_t* handle, crypto_key* key, std::list<cose_alg_t> methods, binary_t const& input,
                                                 binary_t& output) {
    return_t ret = errorcode_t::success;
    cbor_object_encryption cose_encryption;

    ret = cose_encryption.encrypt(handle, key, methods, input, output);
    return ret;
}

return_t cbor_object_signing_encryption::encrypt(cose_context_t* handle, crypto_key* key, cose_alg_t* methods, size_t size_method, binary_t const& input,
                                                 binary_t& output) {
    return_t ret = errorcode_t::success;
    cbor_object_encryption cose_encryption;

    ret = cose_encryption.encrypt(handle, key, methods, size_method, input, output);
    return ret;
}
#endif

return_t cbor_object_signing_encryption::decrypt(cose_context_t* handle, crypto_key* key, binary_t const& input, binary_t& output, bool& result) {
    return_t ret = errorcode_t::success;
    cbor_object_encryption cose_encryption;

    ret = cose_encryption.decrypt(handle, key, input, output, result);
    return ret;
}

return_t cbor_object_signing_encryption::sign(cose_context_t* handle, crypto_key* key, cose_alg_t method, binary_t const& input, binary_t& output) {
    return_t ret = errorcode_t::success;
    cbor_object_signing cose_sign;

    ret = cose_sign.sign(handle, key, method, input, output);
    return ret;
}

return_t cbor_object_signing_encryption::sign(cose_context_t* handle, crypto_key* key, std::list<cose_alg_t> methods, binary_t const& input, binary_t& output) {
    return_t ret = errorcode_t::success;
    cbor_object_signing cose_sign;

    ret = cose_sign.sign(handle, key, methods, input, output);
    return ret;
}

return_t cbor_object_signing_encryption::mac(cose_context_t* handle, crypto_key* key, cose_alg_t method, binary_t const& input, binary_t& output) {
    return_t ret = errorcode_t::success;
    cbor_object_signing cose_sign;

    ret = cose_sign.mac(handle, key, method, input, output);
    return ret;
}

return_t cbor_object_signing_encryption::mac(cose_context_t* handle, crypto_key* key, std::list<cose_alg_t> methods, binary_t const& input, binary_t& output) {
    return_t ret = errorcode_t::success;
    cbor_object_signing cose_sign;

    ret = cose_sign.mac(handle, key, methods, input, output);
    return ret;
}

return_t cbor_object_signing_encryption::verify(cose_context_t* handle, crypto_key* key, binary_t const& input, bool& result) {
    return_t ret = errorcode_t::success;
    cbor_object_signing cose_sign;

    ret = cose_sign.verify(handle, key, input, result);
    return ret;
}

return_t cbor_object_signing_encryption::clear_context(cose_context_t* handle) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        handle->clear();
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::info_of_strcuture(cose_context_t* handle, cose_structure_t& item, int& alg, std::string& kid) {
    return_t ret = errorcode_t::success;

    __try2 {
        alg = cose_alg_t::cose_unknown;
        kid.clear();

        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        //                      alg,kid
        // cose_tag_encrypt     handle::body::multiitems[]::(alg,kid)
        // cose_tag_encrypt0    handle::body::(alg,kid)
        // cose_tag_mac         handle::body::multiitems[]::(alg,kid)
        // cose_tag_mac0        handle::body::(alg,kid)
        // cose_tag_sign        handle::body::multiitems[]::(alg,kid)
        // cose_tag_sign1       handle::body::(alg,kid)

        cbor_object_signing_encryption::parser parser;
        // cose_composer::composer composer;
        parser.finditem(cose_key_t::cose_kid, kid, item.unprotected_map);
        parser.finditem(cose_key_t::cose_alg, alg, item.protected_map);
        if (cose_alg_t::cose_unknown == alg) {
            parser.finditem(cose_key_t::cose_alg, alg, item.unprotected_map);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::preprocess_keyagreement(cose_context_t* handle, crypto_key* key, cose_structure_t& item) {
    return_t ret = errorcode_t::success;
    return_t check = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    cbor_object_signing_encryption::parser parser;
    // cose_composer::composer composer;
    binary_t secret;

    __try2 {
        if (nullptr == handle || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        int alg = 0;
        std::string kid;
        info_of_strcuture(handle, item, alg, kid);

        const hint_cose_algorithm_t* alg_hint = advisor->hintof_cose_algorithm((cose_alg_t)alg);
        if (nullptr == alg_hint) {
            __leave2;
        }

        std::list<cose_structure_t*>::iterator layered_iter;
        for (layered_iter = item.multiitems.begin(); layered_iter != item.multiitems.end(); layered_iter++) {
            cose_structure_t* layered_item = *layered_iter;
            secret = layered_item->binarymap[cose_param_t::cose_param_cek];  // KEK
            if (secret.size()) {
                // secret.resize(alg_hint->enc.ksize);
                break;
            }
        }

        if (0 == secret.size()) {
            // HMAC .. read private key
            // EC/OKP .. do ECDH-ES/ECDH-SS

            cose_group_t group = alg_hint->group;
            crypto_kty_t kty = alg_hint->kty;
            crypto_keychain keychain;
            const EVP_PKEY* epk = nullptr;
            const EVP_PKEY* pkey = keychain.choose(key, kid, kty, check);
            if (nullptr == pkey) {
                handle->debug_flags |= cose_debug_notfound_key;
                __leave2;
            }

            switch (kty) {
                case crypto_kty_t::kty_oct: {
                    crypto_kty_t kty_oct;
                    key->get_privkey(pkey, kty_oct, secret, true);
                } break;
                case crypto_kty_t::kty_ec:

                    if (parser.exist(cose_key_t::cose_static_key_id, item.unprotected_map)) {
                        std::string static_keyid;
                        parser.finditem(cose_key_t::cose_static_key_id, static_keyid, item.unprotected_map);
                        epk = key->find(static_keyid.c_str(), kty);
                    } else {
                        epk = item.epk;
                    }

                    switch (group) {
                        case cose_group_t::cose_group_key_ecdhes_hmac:
                        case cose_group_t::cose_group_key_ecdhss_hmac:
                        case cose_group_t::cose_group_key_ecdhes_aeskw:
                        case cose_group_t::cose_group_key_ecdhss_aeskw:
                            dh_key_agreement(pkey, epk, secret);
                            break;
                        default:
                            break;
                    }

                    break;
                default:
                    break;
            }
        }

        item.binarymap[cose_param_t::cose_param_secret] = secret;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::process_keyagreement(cose_context_t* handle, crypto_key* key, cose_structure_t& item, bool do_encrypt) {
    return_t ret = errorcode_t::success;
    return_t check = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    cbor_object_signing_encryption::parser parser;
    // cose_composer::composer composer;

    __try2 {
        if (nullptr == handle || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        preprocess_keyagreement(handle, key, item);

        cose_structure_t& source = item.parent ? *item.parent : handle->body;

        int alg = 0;
        std::string kid;
        info_of_strcuture(handle, item, alg, kid);

        const hint_cose_algorithm_t* alg_hint = advisor->hintof_cose_algorithm((cose_alg_t)alg);
        const hint_cose_algorithm_t* hint = advisor->hintof_cose_algorithm(source.alg);
        if (nullptr == alg_hint) {
            __leave2;
        }
        crypto_kty_t kty = alg_hint->kty;

        binary_t cek;
        binary_t context;
        binary_t iv;
        binary_t kek;
        binary_t kwiv;
        binary_t salt;
        binary_t secret;

        crypto_keychain keychain;

        if (item.parent) {
            secret = item.binarymap[cose_param_t::cose_param_secret];  // preprocessed secret

            check = parser.finditem(cose_key_t::cose_iv, iv, source.unprotected_map);
            if (errorcode_t::success != check) {
                parser.finditem(cose_key_t::cose_iv, iv, item.unprotected_map);
            }
            parser.finditem(cose_key_t::cose_salt, salt, item.unprotected_map);

            openssl_crypt crypt;
            openssl_hash hash;
            openssl_kdf kdf;

            kwiv.resize(8);
            memset(&kwiv[0], 0xa6, kwiv.size());

            uint16 dgst_klen = 0;
            if (hint) {
                dgst_klen = hint->dgst.klen;
            }
            if (0 == dgst_klen) {
                dgst_klen = alg_hint->dgst.dlen;
            }

            cose_group_t group = alg_hint->group;
            const char* enc_alg = alg_hint->enc.algname;
            const char* digest_alg = alg_hint->dgst.algname;
            uint16 digest_dlen = alg_hint->dgst.dlen;

            // reversing "AAD_hex", "CEK_hex", "Context_hex", "KEK_hex" from https://github.com/cose-wg/Examples

            if (cose_flag_t::cose_flag_allow_debug & handle->flags) {
                constexpr char constexpr_debug_alg[] = "alg %i(group %i) ";
                handle->debug_stream.printf(constexpr_debug_alg, alg, group);
            }

            if (cose_group_t::cose_group_key_direct == group) {
                // RFC 8152 12.1. Direct Encryption
                cek = secret;
            } else if (cose_group_t::cose_group_key_hkdf_hmac == group) {
                // RFC 8152 12.1.2.  Direct Key with KDF
                parser.compose_kdf_context(handle, item, context);

                // using context structure to transform the shared secret into the CEK
                // either the 'salt' parameter of HKDF ot the 'PartyU nonce' parameter of the context structure MUST be present.
                kdf.hmac_kdf(cek, digest_alg, dgst_klen, secret, salt, context);
                // CEK solved
            } else if (cose_group_t::cose_group_key_hkdf_aes == group) {
                parser.compose_kdf_context(handle, item, context);

                // RFC 8152 11.1.  HMAC-Based Extract-and-Expand Key Derivation Function (HKDF)
                // RFC 8152 Table 12: HKDF Algorithms
                //      HKDF AES-MAC-128, AES-CBC-MAC-128, HKDF using AES-MAC as the PRF w/ 128-bit key
                //      HKDF AES-MAC-256, AES-CBC-MAC-256, HKDF using AES-MAC as the PRF w/ 256-bit key

                kdf.hkdf_expand_aes_rfc8152(cek, digest_alg, dgst_klen, secret, context);
            } else if (cose_group_t::cose_group_key_aeskw == group) {
                kek = secret;
                if (do_encrypt) {
                    crypt.encrypt(enc_alg, kek, kwiv, item.bin_payload, cek);
                } else {
                    crypt.decrypt(enc_alg, kek, kwiv, item.bin_payload, cek);
                }
            } else if ((cose_group_t::cose_group_key_ecdhes_hmac == group) || (cose_group_t::cose_group_key_ecdhss_hmac == group)) {
                // RFC 8152 12.4.1. ECDH
                // RFC 8152 11.1.  HMAC-Based Extract-and-Expand Key Derivation Function (HKDF)
                // dh_key_agreement(pkey, epk, secret);

                parser.compose_kdf_context(handle, item, context);

                salt.resize(digest_dlen);
                kdf.hmac_kdf(cek, digest_alg, dgst_klen, secret, salt, context);
            } else if ((cose_group_t::cose_group_key_ecdhes_aeskw == group) || (cose_group_t::cose_group_key_ecdhss_aeskw == group)) {
                // RFC 8152 12.5.1. ECDH
                // RFC 8152 12.2.1. AES Key Wrap
                // dh_key_agreement(pkey, epk, secret);

                parser.compose_kdf_context(handle, item, context);

                salt.resize(digest_dlen);
                kdf.hmac_kdf(kek, digest_alg, dgst_klen, secret, salt, context);

                // 12.5.  Key Agreement with Key Wrap
                if (do_encrypt) {
                    crypt.encrypt(enc_alg, kek, kwiv, item.bin_payload, cek);
                } else {
                    crypt.decrypt(enc_alg, kek, kwiv, item.bin_payload, cek);
                }
            } else if (cose_group_t::cose_group_key_rsa_oaep == group) {
                crypt_enc_t mode;
                switch (alg) {
                    case cose_alg_t::cose_rsaoaep1:
                        mode = crypt_enc_t::rsa_oaep;
                        break;
                    case cose_alg_t::cose_rsaoaep256:
                        mode = crypt_enc_t::rsa_oaep256;
                        break;
                    case cose_alg_t::cose_rsaoaep512:
                        mode = crypt_enc_t::rsa_oaep512;
                        break;
                    default:
                        break;
                }
                const EVP_PKEY* pkey = keychain.choose(key, kid, kty, check);
                if (do_encrypt) {
                    crypt.encrypt(pkey, item.bin_payload, cek, mode);
                } else {
                    crypt.decrypt(pkey, item.bin_payload, cek, mode);
                }
            }

            item.binarymap[cose_param_t::cose_param_cek] = cek;

            if (cose_flag_t::cose_flag_allow_debug & handle->flags) {
                item.binarymap[cose_param_t::cose_param_context] = context;
                item.binarymap[cose_param_t::cose_param_iv] = iv;
                item.binarymap[cose_param_t::cose_param_kek] = kek;
                item.binarymap[cose_param_t::cose_param_secret] = secret;
                item.binarymap[cose_param_t::cose_param_salt] = salt;
            }
        } else {
            binary_t cek;
            const EVP_PKEY* pkey = keychain.choose(key, kid, kty, check);
            key->get_privkey(pkey, kty, cek, true);

            handle->binarymap[cose_param_t::cose_param_cek] = cek;
        }

#define dump(x)                                                                 \
    if (x.size()) {                                                             \
        dump_memory(x, &bs, 16, 4);                                             \
        printf("  %s\n%s\n    %s\n", #x, bs.c_str(), base16_encode(x).c_str()); \
    }

        if (cose_flag_t::cose_flag_allow_debug & handle->flags) {
            basic_stream bs;
            dump(cek);
            dump(context);
            dump(iv);
            dump(kek);
            dump(salt);
            dump(secret);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

cbor_object_signing_encryption::parser::parser() {}

cbor_object_signing_encryption::parser::~parser() {}

return_t cbor_object_signing_encryption::parser::parse(cose_context_t* handle, binary_t const& input) {
    return_t ret = errorcode_t::success;
    return_t check = errorcode_t::success;
    cbor_reader reader;
    cbor_reader_context_t* reader_context = nullptr;
    cbor_object* root = nullptr;
    const char* kid = nullptr;
    std::set<bool> results;
    cose_advisor* coseadvisor = cose_advisor::get_instance();

    __try2 {
        clear_context(handle);

        ret = reader.open(&reader_context);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = reader.parse(reader_context, input);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = reader.publish(reader_context, &root);
        if (errorcode_t::success != ret) {
            __leave2_trace(ret);
        }

        if ((root->tagged()) && (cbor_type_t::cbor_type_array == root->type())) {
            // do nothing
        } else {
            ret = errorcode_t::request;
            __leave2_trace(ret);
        }

        int elemof_cbor = root->size();
        cbor_tag_t cbor_tag = root->tag_value();

        typedef return_t (cbor_object_signing_encryption::parser::*doparse_handler)(cose_context_t * handle, cbor_object * object);
        typedef std::map<cose_message_type_t, doparse_handler> cose_message_handler_map_t;
        cose_message_handler_map_t cose_message_handler_map;

        cose_message_handler_map[cose_message_protected] = &cbor_object_signing_encryption::parser::doparse_protected;
        cose_message_handler_map[cose_message_unprotected] = &cbor_object_signing_encryption::parser::doparse_unprotected;
        cose_message_handler_map[cose_message_payload] = &cbor_object_signing_encryption::parser::doparse_payload;
        cose_message_handler_map[cose_message_singleitem] = &cbor_object_signing_encryption::parser::doparse_singleitem;
        cose_message_handler_map[cose_message_layered] = &cbor_object_signing_encryption::parser::doparse_multiitems;

        const hint_cose_message_structure_t* cose_message_map = coseadvisor->hintof(cbor_tag);
        if (nullptr == cose_message_map) {
            ret = errorcode_t::bad_data;
            __leave2;
        }
        if (cose_message_map->elemof_cbor != elemof_cbor) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        handle->cbor_tag = cbor_tag;

        for (int i = 0; i < cose_message_map->elemof_cbor; i++) {
            cbor_object* item = (*(cbor_array*)root)[i];
            cose_message_type_t typeof_item = cose_message_map->typeof_item[i];
            doparse_handler handler = nullptr;
            handler = cose_message_handler_map[typeof_item];

            ret = (this->*handler)(handle, item);
            if (errorcode_t::success != ret) {
                break;
            }
        }
    }
    __finally2 {
        reader.close(reader_context);

        if (root) {
            root->release();
        }
    }
    return ret;
}

bool cbor_object_signing_encryption::parser::exist(int key, cose_variantmap_t const& from) {
    bool ret_value = false;
    return_t ret = errorcode_t::success;
    basic_stream cosekey;
    variant_t vt;

    maphint_const<int, variant_t> hint(from);
    ret = hint.find(key, &vt);
    if (errorcode_t::success == ret) {
        ret_value = true;
    }
    return ret_value;
}

return_t cbor_object_signing_encryption::parser::finditem(int key, int& value, cose_variantmap_t const& from) {
    return_t ret = errorcode_t::success;
    basic_stream cosekey;
    variant_t vt;

    maphint_const<int, variant_t> hint(from);
    ret = hint.find(key, &vt);
    if (errorcode_t::success == ret) {
        value = t_variant_to_int<int>(vt);
    }
    return ret;
}

return_t cbor_object_signing_encryption::parser::finditem(int key, std::string& value, cose_variantmap_t const& from) {
    return_t ret = errorcode_t::success;
    variant_t vt;

    maphint_const<int, variant_t> hint(from);
    ret = hint.find(key, &vt);
    if (errorcode_t::success == ret) {
        variant_string(vt, value);
    }
    return ret;
}

return_t cbor_object_signing_encryption::parser::finditem(int key, binary_t& value, cose_variantmap_t const& from) {
    return_t ret = errorcode_t::success;
    variant_t vt;

    maphint_const<int, variant_t> hint(from);
    ret = hint.find(key, &vt);
    if (errorcode_t::success == ret) {
        variant_binary(vt, value);
    }
    return ret;
}

return_t cbor_object_signing_encryption::parser::compose_enc_structure(cose_context_t* handle, binary_t& authenticated_data) {
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
        authenticated_data.clear();

        root = new cbor_array();

        uint8 tag = handle->cbor_tag;
        if (cbor_tag_t::cose_tag_encrypt == tag) {
            *root << new cbor_data("Encrypt");
        } else if (cbor_tag_t::cose_tag_encrypt0 == tag) {
            *root << new cbor_data("Encrypt0");
        } else {
            ret = errorcode_t::request;
            __leave2;
        }

        *root << new cbor_data(handle->body.bin_protected) << new cbor_data(handle->binarymap[cose_param_t::cose_external]);

        pub.publish(root, &authenticated_data);
    }
    __finally2 {
        if (root) {
            root->release();
        }
    }
    return ret;
}

cbor_data* cbor_object_signing_encryption::parser::docompose_kdf_context_item(cose_context_t* handle, cose_structure_t& item, cose_key_t key,
                                                                              cose_param_t shared) {
    return_t ret = errorcode_t::success;
    return_t check = errorcode_t::success;
    cbor_object_signing_encryption::parser parser;
    // cose_composer::composer composer;
    cbor_data* data = nullptr;
    binary_t bin;
    check = parser.finditem(key, bin, item.unprotected_map);
    if (errorcode_t::success != check) {
        bin = handle->binarymap[shared];
    }
    if (bin.size()) {
        data = new cbor_data(bin);
    } else {
        data = new cbor_data();  // null(F6)
    }
    return data;
}

return_t cbor_object_signing_encryption::parser::compose_kdf_context(cose_context_t* handle, cose_structure_t& item, binary_t& kdf_context) {
    return_t ret = errorcode_t::success;
    return_t check = errorcode_t::success;

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
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        int algid = 0;
        int recp_alg = 0;

        cbor_object_signing_encryption::parser parser;
        // cose_composer::composer composer;

        cose_structure_t& source = item.parent ? *item.parent : handle->body;

        parser.finditem(cose_key_t::cose_alg, recp_alg, item.protected_map);
        // a key wrap algorithm identifier or a content encryption algorithm identifier
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
                check = parser.finditem(cose_key_t::cose_alg, algid, source.protected_map);
                if (errorcode_t::success != check) {
                    parser.finditem(cose_key_t::cose_alg, algid, source.unprotected_map);
                }
                break;
        }

        int keylen = 0;
        switch (algid) {
            case cose_aes128kw:
            case cose_aes128gcm:
            case cose_aesmac_128_64:
            case cose_aesmac_128_128:
            case cose_aesccm_16_64_128:
            case cose_aesccm_64_64_128:
            case cose_aesccm_16_128_128:
            case cose_aesccm_64_128_128:
            case cose_hkdf_sha256:
            case cose_hkdf_aes128:
            case cose_ecdhes_hkdf_256:
            case cose_ecdhss_hkdf_256:
            case cose_hs256_64:
                keylen = 128;
                break;
            case cose_aes192kw:
            case cose_aes192gcm:
                keylen = 192;
                break;
            case cose_aes256kw:
            case cose_aes256gcm:
            case cose_aesmac_256_64:
            case cose_aesmac_256_128:
            case cose_aesccm_16_64_256:
            case cose_aesccm_64_64_256:
            case cose_aesccm_16_128_256:
            case cose_aesccm_64_128_256:
            case cose_hkdf_sha512:
            case cose_hkdf_aes256:
            case cose_ecdhes_hkdf_512:
            case cose_ecdhss_hkdf_512:
            case cose_hs256:
                keylen = 256;
                break;
            case cose_hs384:
                keylen = 384;
                break;
            case cose_hs512:
                keylen = 512;
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
            *partyu << docompose_kdf_context_item(handle, item, cose_key_t::cose_partyu_id, cose_param_t::cose_unsent_apu_id)
                    << docompose_kdf_context_item(handle, item, cose_key_t::cose_partyu_nonce, cose_param_t::cose_unsent_apu_nonce)
                    << docompose_kdf_context_item(handle, item, cose_key_t::cose_partyu_other, cose_param_t::cose_unsent_apu_other);
        }
        // PartyVInfo
        {
            *partyv << docompose_kdf_context_item(handle, item, cose_key_t::cose_partyv_id, cose_param_t::cose_unsent_apv_id)
                    << docompose_kdf_context_item(handle, item, cose_key_t::cose_partyv_nonce, cose_param_t::cose_unsent_apv_nonce)
                    << docompose_kdf_context_item(handle, item, cose_key_t::cose_partyv_other, cose_param_t::cose_unsent_apv_other);
        }
        // SuppPubInfo
        {
            *pub << new cbor_data(keylen) << new cbor_data(item.bin_protected);
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
        publisher.publish(root, &kdf_context);
    }
    __finally2 {
        if (root) {
            root->release();
        }
    }

    return ret;
}

return_t cbor_object_signing_encryption::parser::compose_sig_structure(cose_context_t* handle, cose_structure_t& item, binary_t& tobesigned) {
    return_t ret = errorcode_t::success;
    cbor_encode encoder;
    cbor_publisher pub;
    cbor_array* root = nullptr;

    // RFC 8152 4.4.  Signing and Verification Process
    // Sig_structure = [
    //    context : "Signature" / "Signature1" / "CounterSignature",
    //    body_protected : empty_or_serialized_map,
    //    ? sign_protected : empty_or_serialized_map,
    //    external_aad : bstr,
    //    payload : bstr
    // ]

    __try2 {
        tobesigned.clear();

        root = new cbor_array();

        uint8 tag = handle->cbor_tag;
        if (cbor_tag_t::cose_tag_sign == tag) {
            *root << new cbor_data("Signature");
        } else if (cbor_tag_t::cose_tag_sign1 == tag) {
            *root << new cbor_data("Signature1");
        } else {
            ret = errorcode_t::request;
            __leave2;
        }

        *root << new cbor_data(handle->body.bin_protected);
        if (cbor_tag_t::cose_tag_sign == tag) {
            // This field is omitted for the COSE_Sign1 signature structure.
            if (item.parent) {
                *root << new cbor_data(item.bin_protected);
            }
        }
        *root << new cbor_data(handle->binarymap[cose_param_t::cose_external]) << new cbor_data(handle->body.bin_payload);

        pub.publish(root, &tobesigned);
    }
    __finally2 {
        if (root) {
            root->release();
        }
    }

    return ret;
}

return_t cbor_object_signing_encryption::parser::compose_mac_structure(cose_context_t* handle, binary_t& tomac) {
    return_t ret = errorcode_t::success;
    cbor_encode encoder;
    cbor_publisher pub;
    cbor_array* root = nullptr;

    // RFC 8152 6.3.  How to Compute and Verify a MAC
    // MAC_structure = [
    //     context : "MAC" / "MAC0",
    //     protected : empty_or_serialized_map,
    //     external_aad : bstr,
    //     payload : bstr
    // ]

    __try2 {
        tomac.clear();

        root = new cbor_array();

        uint8 tag = handle->cbor_tag;
        if (cbor_tag_t::cose_tag_mac == tag) {
            *root << new cbor_data("MAC");
        } else if (cbor_tag_t::cose_tag_mac0 == tag) {
            *root << new cbor_data("MAC0");
        } else {
            ret = errorcode_t::request;
            __leave2;
        }

        cose_structure_t& item = handle->body;

        *root << new cbor_data(item.bin_protected) << new cbor_data(handle->binarymap[cose_param_t::cose_external]) << new cbor_data(item.bin_payload);

        pub.publish(root, &tomac);
    }
    __finally2 {
        if (root) {
            root->release();
        }
    }

    return ret;
}

return_t cbor_object_signing_encryption::parser::doparse_protected(cose_context_t* handle, cbor_object* object) {
    return_t ret = errorcode_t::success;
    return_t check = errorcode_t::success;
    __try2 {
        if (nullptr == handle || nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cbor_data* cbor_protected = cbor_typeof<cbor_data>(object, cbor_type_t::cbor_type_data);
        if (nullptr == cbor_protected) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        cose_structure_t& item = handle->body;

        variant_binary(cbor_protected->data(), item.bin_protected);
        doparse_binary(item.bin_protected, item.protected_map);

        int alg = 0;
        check = finditem(cose_key_t::cose_alg, alg, item.protected_map);
        item.alg = (cose_alg_t)alg;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::parser::doparse_unprotected(cose_context_t* handle, cbor_object* object) {
    return_t ret = errorcode_t::success;
    return_t check = errorcode_t::success;
    __try2 {
        if (nullptr == handle || nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cose_structure_t& item = handle->body;

        cbor_map* cbor_unprotected = cbor_typeof<cbor_map>(object, cbor_type_t::cbor_type_map);
        if (nullptr == cbor_unprotected) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        doparse_map(cbor_unprotected, item.unprotected_map);

        if (cose_alg_t::cose_unknown == item.alg) {
            int alg = 0;
            check = finditem(cose_key_t::cose_alg, alg, item.unprotected_map);
            item.alg = (cose_alg_t)alg;
        }

        std::string kid;
        check = finditem(cose_key_t::cose_kid, kid, item.unprotected_map);
        item.kid = kid;

        if (cose_flag_t::cose_flag_allow_debug & handle->flags) {
            constexpr char constexpr_debug_alg[] = "*alg:%i ";
            handle->debug_stream.printf(constexpr_debug_alg, item.alg);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::parser::doparse_payload(cose_context_t* handle, cbor_object* object) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == handle || nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cose_structure_t& item = handle->body;

        cbor_data* cbor_payload = cbor_typeof<cbor_data>(object, cbor_type_t::cbor_type_data);
        if (nullptr == cbor_payload) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        variant_binary(cbor_payload->data(), item.bin_payload);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::parser::doparse_singleitem(cose_context_t* handle, cbor_object* object) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == handle || nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cose_structure_t& item = handle->body;

        cbor_data* cbor_item = cbor_typeof<cbor_data>(object, cbor_type_t::cbor_type_data);
        if (nullptr == cbor_item) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        variant_binary(cbor_item->data(), item.singleitem);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::parser::doparse_multiitems(cose_context_t* handle, cbor_object* object) {
    return_t ret = errorcode_t::success;
    return_t check = errorcode_t::success;

    __try2 {
        if (nullptr == handle || nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cose_structure_t& item = handle->body;

        cbor_array* cbor_items = cbor_typeof<cbor_array>(object, cbor_type_t::cbor_type_array);  // [+signature], [+recipient]
        if (nullptr == cbor_items) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        size_t size_array = cbor_items->size();
        for (size_t i = 0; i < size_array; i++) {
            cbor_array* cbor_item = cbor_typeof<cbor_array>((*cbor_items)[i], cbor_type_t::cbor_type_array);  // [signature], [recipient]
            cose_structure_t* part = nullptr;
            __try_new_catch_only(part, new cose_structure_t);
            if (nullptr == part) {
                ret = errorcode_t::out_of_memory;
                break;
            }
            check = doparse_multiitem(cbor_item, *part);
            item.add(part);
            if (errorcode_t::success == check) {
                if (cbor_item->size() == 4) {
                    // RFC 8152 Appendix B
                    // two layered structure
                    cbor_array* cbor_recipients = cbor_typeof<cbor_array>((*cbor_item)[3], cbor_type_t::cbor_type_array);  // [+recipients]
                    size_t size_recipients = cbor_recipients->size();
                    for (size_t j = 0; j < size_recipients; j++) {
                        cbor_array* cbor_recipient = cbor_typeof<cbor_array>((*cbor_recipients)[j], cbor_type_t::cbor_type_array);
                        cose_structure_t* layered_part = nullptr;
                        __try_new_catch_only(layered_part, new cose_structure_t);
                        if (nullptr == layered_part) {
                            ret = errorcode_t::out_of_memory;
                            break;
                        }
                        doparse_multiitem(cbor_recipient, *layered_part);
                        part->add(layered_part);
                    }
                    if (errorcode_t::success != ret) {
                        break;
                    }
                }
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::parser::doparse_multiitem(cbor_array* object, cose_structure_t& item) {
    return_t ret = errorcode_t::success;
    return_t check = errorcode_t::success;

    __try2 {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (object->size() < 3) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        cbor_data* cbor_protected = cbor_typeof<cbor_data>((*object)[0], cbor_type_t::cbor_type_data);
        cbor_map* cbor_unprotected = cbor_typeof<cbor_map>((*object)[1], cbor_type_t::cbor_type_map);
        cbor_data* cbor_payload = cbor_typeof<cbor_data>((*object)[2], cbor_type_t::cbor_type_data);

        if (nullptr == cbor_protected || nullptr == cbor_unprotected || nullptr == cbor_payload) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        variant_binary(cbor_protected->data(), item.bin_protected);
        variant_binary(cbor_payload->data(), item.bin_payload);
        doparse_binary(item.bin_protected, item.protected_map);
        doparse_unprotected(cbor_unprotected, item);

        int alg = 0;
        check = finditem(cose_key_t::cose_alg, alg, item.protected_map);
        if (errorcode_t::success != check) {
            check = finditem(cose_key_t::cose_alg, alg, item.unprotected_map);
        }
        item.alg = (cose_alg_t)alg;

        std::string kid;
        check = finditem(cose_key_t::cose_kid, kid, item.unprotected_map);
        item.kid = kid;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::parser::doparse_unprotected(cbor_map* root, cose_structure_t& item) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        size_t size_map = root->size();
        for (size_t i = 0; i < size_map; i++) {
            cbor_pair* pair = (*root)[i];
            cbor_data* pair_key = (cbor_data*)pair->left();
            cbor_object* pair_value = (cbor_object*)pair->right();
            cbor_type_t type_value = pair_value->type();
            int keyid = 0;
            cose_variantmap_t dh_key;

            keyid = t_variant_to_int<int>(pair_key->data());

            if (cbor_type_t::cbor_type_data == type_value) {
                cbor_data* data = (cbor_data*)pair_value;
                variant_t vt;
                variant_copy(vt, data->data());
                item.unprotected_map.insert(std::make_pair(keyid, vt));
            } else if (cbor_type_t::cbor_type_map == type_value) {
                cbor_map* map_value = (cbor_map*)pair->right();
                if (-1 == keyid || -2 == keyid) {
                    // -1 cose_ephemeral_key
                    // -2 cose_static_key

                    doparse_map(map_value, dh_key);

                    return_t check = errorcode_t::success;
                    variant_t vt;
                    maphint<int, variant_t> hint(dh_key);
                    check = hint.find(cose_key_lable_t::cose_lable_kty, &vt);
                    int kty = t_variant_to_int<int>(vt);
                    if (cose_kty_t::cose_kty_ec2 == kty || cose_kty_t::cose_kty_okp == kty) {
                        int crv = 0;
                        binary_t bin_x;
                        binary_t bin_y;
                        binary_t bin_d;
                        bool ysign = true;

                        check = hint.find(cose_key_lable_t::cose_ec_crv, &vt);
                        crv = t_variant_to_int<int>(vt);
                        check = hint.find(cose_key_lable_t::cose_ec_x, &vt);
                        variant_binary(vt, bin_x);
                        check = hint.find(cose_key_lable_t::cose_ec_y, &vt);
                        if (TYPE_BOOL == vt.type) {
                            ysign = vt.data.b;
                        } else {
                            variant_binary(vt, bin_y);
                        }

                        uint32 nid = advisor->curveof((cose_ec_curve_t)crv);

                        crypto_key key;
                        crypto_keychain keychain;
                        if (bin_y.size()) {
                            keychain.add_ec(&key, nullptr, nullptr, nid, bin_x, bin_y, bin_d);
                        } else {
                            keychain.add_ec(&key, nullptr, nullptr, nid, bin_x, ysign ? 1 : 0, bin_d);
                        }
                        item.epk = key.any(true);
                    }
                }
            }
            cose_variantmap_free(dh_key);
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t cbor_object_signing_encryption::parser::doparse_binary(binary_t const& data, cose_variantmap_t& vtl) {
    return_t ret = errorcode_t::success;
    cbor_object* root = nullptr;

    __try2 {
        ret = cbor_parse(&root, data);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        if (cbor_type_t::cbor_type_map != root->type()) {
            ret = errorcode_t::bad_data;
            __leave2_trace(ret);
        }

        ret = doparse_map((cbor_map*)root, vtl);
    }
    __finally2 {
        if (root) {
            root->release();
        }
    }
    return ret;
}

return_t cbor_object_signing_encryption::parser::doparse_map(cbor_map* root, cose_variantmap_t& vtl) {
    return_t ret = errorcode_t::success;

    __try2 {
        size_t size_map = root->size();
        for (size_t i = 0; i < size_map; i++) {
            cbor_pair* pair = (*root)[i];

            cbor_data* pair_key = pair->left();
            int keyid = 0;
            keyid = t_variant_to_int<int>(pair_key->data());

            cbor_object* pair_value = pair->right();
            variant_t vt;
            cbor_type_t type_value = pair_value->type();

            if (cbor_type_t::cbor_type_data == type_value) {
                cbor_data* data = cbor_typeof<cbor_data>(pair_value, cbor_type_t::cbor_type_data);
                if (data) {
                    variant_copy(vt, data->data());
                    vtl.insert(std::make_pair(keyid, vt));
                }
            } else if (cbor_type_t::cbor_type_simple == type_value) {
                cbor_simple* simple = cbor_typeof<cbor_simple>(pair_value, cbor_type_t::cbor_type_simple);
                if (simple) {
                    cbor_simple_t simple_type = simple->simple_type();
                    switch (simple_type) {
                        case cbor_simple_true:
                            variant_set_bool(vt, true);
                            vtl.insert(std::make_pair(keyid, vt));
                            break;
                        case cbor_simple_false:
                            variant_set_bool(vt, false);
                            vtl.insert(std::make_pair(keyid, vt));
                            break;
                        default:
                            break;
                    }
                }
            }
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

}  // namespace crypto
}  // namespace hotplace
