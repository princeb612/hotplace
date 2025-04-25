/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 7517 JSON Web Key (JWK)
 *  RFC 8037 CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JSON Object Signing and Encryption (JOSE)
 *
 * Revision History
 * Date         Name                Description
 */

#include <fstream>
#include <sdk/base/basic/base64.hpp>
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/crypto_keychain.hpp>
#include <sdk/crypto/basic/evp_key.hpp>
#include <sdk/crypto/basic/openssl_sdk.hpp>
#include <sdk/crypto/jose/json_web_key.hpp>
#include <sdk/io/basic/json.hpp>
#include <sdk/io/stream/file_stream.hpp>

namespace hotplace {
namespace crypto {

json_web_key::json_web_key() : crypto_keychain() {
    // do nothing
}

json_web_key::~json_web_key() {
    // do nothing
}

return_t json_web_key::load(crypto_key* cryptokey, keyflag_t mode, const char* buffer, size_t size, const keydesc& desc, int flag) {
    return_t ret = errorcode_t::success;
    if (key_ownspec == mode) {
        ret = load_pem(cryptokey, buffer, size, desc, flag);
    } else {
        ret = crypto_keychain::load(cryptokey, mode, buffer, size, desc, flag);
    }
    return ret;
}

return_t json_web_key::load_pem(crypto_key* cryptokey, const char* buffer, size_t size, const keydesc& desc, int flag) {
    return_t ret = errorcode_t::success;
    json_t* root = nullptr;

    __try2 {
        if (nullptr == buffer) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = json_open_stream(&root, buffer);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        json_t* keys_node = json_object_get(root, "keys");
        if (nullptr != keys_node) {
            if (JSON_ARRAY != json_typeof(keys_node)) {
                ret = errorcode_t::bad_data;
                __leave2;
            }

            size_t size = json_array_size(keys_node);
            for (size_t i = 0; i < size; i++) {
                json_t* temp = json_array_get(keys_node, i);
                read_json_keynode(cryptokey, temp);
            }  // json_array_size
        } else {
            read_json_keynode(cryptokey, root);
        }
    }
    __finally2 {
        if (root) {
            json_decref(root);
        }
    }
    return ret;
}

return_t json_web_key::write(crypto_key* cryptokey, keyflag_t mode, stream_t* stream, int flag) {
    return_t ret = errorcode_t::success;
    if (key_ownspec == mode) {
        ret = write(cryptokey, stream, flag);
    } else {
        ret = crypto_keychain::write(cryptokey, mode, stream, flag);
    }
    return ret;
}

return_t json_web_key::read_json_keynode(crypto_key* cryptokey, json_t* json) {
    return_t ret = errorcode_t::success;
    json_t* temp = json;
    crypto_keychain keyset;

    __try2 {
        if (nullptr == cryptokey || nullptr == temp) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const char* kty = nullptr;
        const char* kid = nullptr;
        const char* use = nullptr;
        const char* alg = nullptr;
        json_unpack(temp, "{s:s}", "kty", &kty);
        json_unpack(temp, "{s:s}", "kid", &kid);
        json_unpack(temp, "{s:s}", "use", &use);
        json_unpack(temp, "{s:s}", "alg", &alg);

        crypto_use_t usage = crypto_use_t::use_any;
        if (nullptr != use) {
            if (0 == strcmp(use, "sig")) {
                usage = crypto_use_t::use_sig;
            } else if (0 == strcmp(use, "enc")) {
                usage = crypto_use_t::use_enc;
            }
        }

        if (nullptr != kty) {
            keydesc desc(kid, alg, usage);
            if (0 == strcmp(kty, "oct")) {
                const char* k_value = nullptr;
                json_unpack(temp, "{s:s}", "k", &k_value);

                add_oct_b64u(cryptokey, k_value, desc);
            } else if (0 == strcmp(kty, "RSA")) {
                const char* n_value = nullptr;
                const char* e_value = nullptr;
                const char* d_value = nullptr;
                json_unpack(temp, "{s:s,s:s,s:s}", "n", &n_value, "e", &e_value, "d", &d_value);

                const char* p_value = nullptr;
                const char* q_value = nullptr;
                const char* dp_value = nullptr;
                const char* dq_value = nullptr;
                const char* qi_value = nullptr;
                json_unpack(temp, "{s:s,s:s,s:s,s:s,s:s}", "p", &p_value, "q", &q_value, "dp", &dp_value, "dq", &dq_value, "qi", &qi_value);

                add_rsa_b64u(cryptokey, nid_rsa, n_value, e_value, d_value, p_value, q_value, dp_value, dq_value, qi_value, desc);
            } else if (0 == strcmp(kty, "EC")) {
                const char* crv_value = nullptr;
                const char* x_value = nullptr;
                const char* y_value = nullptr;
                const char* d_value = nullptr;
                json_unpack(temp, "{s:s,s:s,s:s,s:s}", "crv", &crv_value, "x", &x_value, "y", &y_value, "d", &d_value);

                add_ec_b64u(cryptokey, crv_value, x_value, y_value, d_value, desc);
            } else if (0 == strcmp(kty, "OKP")) {
                const char* crv_value = nullptr;
                const char* x_value = nullptr;
                const char* d_value = nullptr;
                json_unpack(temp, "{s:s,s:s,s:s}", "crv", &crv_value, "x", &x_value, "d", &d_value);

                add_ec_b64u(cryptokey, crv_value, x_value, nullptr, d_value, desc);
            } else {
                // do nothing
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

typedef struct _json_mapper_item_t {
    crypto_kty_t type;
    crypto_key_object key;
    binary_t pub1;
    binary_t pub2;
    binary_t priv;
} json_mapper_item_t;

typedef std::list<json_mapper_item_t> json_mapper_items_t;

typedef struct _json_mapper_t {
    int flag;
    json_mapper_items_t items;
} json_mapper_t;

static void jwk_serialize_item(int flag, const json_mapper_item_t& item, json_t* json_item) {
    crypto_advisor* advisor = crypto_advisor::get_instance();

    auto pkey = item.key.get_pkey();

    /* kty */
    json_object_set_new(json_item, "kty", json_string(nameof_key_type(item.type)));

    /* kid */
    if (item.key.get_desc().get_kid_str().size()) {
        json_object_set_new(json_item, "kid", json_string(item.key.get_desc().get_kid_cstr()));
    }

    /* use */
    if (crypto_use_t::use_sig == item.key.get_desc().get_use()) {
        json_object_set_new(json_item, "use", json_string("sig"));
    }
    if (crypto_use_t::use_enc == item.key.get_desc().get_use()) {
        json_object_set_new(json_item, "use", json_string("enc"));
    }

    if (item.key.get_desc().get_alg_str().size()) {
        json_object_set_new(json_item, "alg", json_string(item.key.get_desc().get_alg_cstr()));
    }

    std::string curve_name;

    if (kindof_ecc(item.type)) {
        advisor->nameof_ec_curve(pkey, curve_name);
    }

    /* param */
    if (crypto_kty_t::kty_oct == item.type) {
        json_object_set_new(json_item, "k", json_string(base64_encode(item.priv, encoding_t::encoding_base64url).c_str()));
    } else if (crypto_kty_t::kty_rsa == item.type) {
        json_object_set_new(json_item, "n", json_string(base64_encode(item.pub1, encoding_t::encoding_base64url).c_str()));
        json_object_set_new(json_item, "e", json_string(base64_encode(item.pub2, encoding_t::encoding_base64url).c_str()));
        if (false == item.priv.empty()) {
            json_object_set_new(json_item, "d", json_string(base64_encode(item.priv, encoding_t::encoding_base64url).c_str()));
        }
    } else if (crypto_kty_t::kty_ec == item.type) {
        json_object_set_new(json_item, "crv", json_string(curve_name.c_str()));
        json_object_set_new(json_item, "x", json_string(base64_encode(item.pub1, encoding_t::encoding_base64url).c_str()));
        json_object_set_new(json_item, "y", json_string(base64_encode(item.pub2, encoding_t::encoding_base64url).c_str()));
        if (false == item.priv.empty()) {
            json_object_set_new(json_item, "d", json_string(base64_encode(item.priv, encoding_t::encoding_base64url).c_str()));
        }
    } else if (crypto_kty_t::kty_okp == item.type) {
        json_object_set_new(json_item, "crv", json_string(curve_name.c_str()));
        json_object_set_new(json_item, "x", json_string(base64_encode(item.pub1, encoding_t::encoding_base64url).c_str()));
        if (false == item.priv.empty()) {
            json_object_set_new(json_item, "d", json_string(base64_encode(item.priv, encoding_t::encoding_base64url).c_str()));
        }
    }
}

template <typename TYPE>
return_t jwk_serialize_t(json_mapper_t mapper, void (*callback)(char* data, TYPE& parameter), TYPE& param) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == callback) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        size_t size = mapper.items.size();
        if (0 == size) {
            ret = errorcode_t::no_data;
            __leave2;
        }

        json_t* json_root = json_object();
        if (json_root) {
            if (1 == size) {
                json_mapper_item_t& item = mapper.items.front();
                jwk_serialize_item(mapper.flag, item, json_root);
            } else {
                auto advisor = crypto_advisor::get_instance();
                json_t* json_keys = json_array();
                if (json_keys) {
                    for (const auto& item : mapper.items) {
                        auto pkey = item.key.get_pkey();
                        auto hint = advisor->hintof_curve_eckey(pkey);
                        if (hint && (CURVE_SUPPORT_JOSE & hint->flags)) {
                            // do nothing
                        } else {
                            continue;
                        }

                        json_t* json_key = json_object();

                        if (json_key) {
                            jwk_serialize_item(mapper.flag, item, json_key);
                            json_array_append_new(json_keys, json_key);
                        }
                    }
                    json_object_set_new(json_root, "keys", json_keys);
                }
            }
            char* contents = json_dumps(json_root, JOSE_JSON_FORMAT);
            if (contents) {
                callback(contents, param);
                free(contents);
            }
            json_decref(json_root);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

static void json_writer(crypto_key_object* key, void* param) {
    json_mapper_t* mapper = (json_mapper_t*)param;

    __try2 {
        if (nullptr == key || nullptr == param) {
            __leave2;
        }

        // preserve leading zero
        json_mapper_item_t item;
        item.key = *key;
        crypto_key::get_key(key->get_pkey(), mapper->flag, item.type, item.pub1, item.pub2, item.priv, true);
        switch (item.type) {
            case kty_oct:
            case kty_rsa:
            case kty_ec:
            case kty_okp:
                mapper->items.push_back(item);
                break;
            default:
                break;
        }
    }
    __finally2 {
        // do nothing
    }
    // do not return
}

return_t json_web_key::write(crypto_key* cryptokey, std::string& buf, int flag) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        buf.clear();

        json_mapper_t mapper;

        mapper.flag = flag;
        cryptokey->for_each(json_writer, &mapper);

        auto lambda = [](char* data, std::string& buffer) -> void { buffer = data; };
        jwk_serialize_t<std::string>(mapper, lambda, buf);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t json_web_key::write(crypto_key* cryptokey, stream_t* buf, int flag) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == cryptokey || nullptr == buf) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        buf->clear();

        json_mapper_t mapper;

        mapper.flag = flag;
        cryptokey->for_each(json_writer, &mapper);

        auto lambda = [](char* data, stream_t*& stream) -> void { stream->printf("%s", data); };
        jwk_serialize_t<stream_t*>(mapper, lambda, buf);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
