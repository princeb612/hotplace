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

return_t json_web_key::load(crypto_key* crypto_key, const char* buffer, int flags) {
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
                read_json_keynode(crypto_key, temp);
            }  // json_array_size
        } else {
            read_json_keynode(crypto_key, root);
        }
    }
    __finally2 {
        if (root) {
            json_decref(root);
        }
    }
    return ret;
}

return_t json_web_key::read_json_keynode(crypto_key* crypto_key, json_t* json) {
    return_t ret = errorcode_t::success;
    json_t* temp = json;
    crypto_keychain keyset;

    __try2 {
        if (nullptr == crypto_key || nullptr == temp) {
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
            if (0 == strcmp(kty, "oct")) {
                const char* k_value = nullptr;
                json_unpack(temp, "{s:s}", "k", &k_value);

                add_oct_b64u(crypto_key, kid, alg, k_value, usage);
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

                add_rsa_b64u(crypto_key, kid, alg, n_value, e_value, d_value, p_value, q_value, dp_value, dq_value, qi_value, usage);
            } else if (0 == strcmp(kty, "EC")) {
                const char* crv_value = nullptr;
                const char* x_value = nullptr;
                const char* y_value = nullptr;
                const char* d_value = nullptr;
                json_unpack(temp, "{s:s,s:s,s:s,s:s}", "crv", &crv_value, "x", &x_value, "y", &y_value, "d", &d_value);

                add_ec_b64u(crypto_key, kid, alg, crv_value, x_value, y_value, d_value, usage);
            } else if (0 == strcmp(kty, "OKP")) {
                const char* crv_value = nullptr;
                const char* x_value = nullptr;
                const char* d_value = nullptr;
                json_unpack(temp, "{s:s,s:s,s:s}", "crv", &crv_value, "x", &x_value, "d", &d_value);

                add_ec_b64u(crypto_key, kid, alg, crv_value, x_value, nullptr, d_value, usage);
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

static void jwk_serialize_item(int flag, json_mapper_item_t item, json_t* json_item) {
    crypto_advisor* advisor = crypto_advisor::get_instance();

    /* kty */
    json_object_set_new(json_item, "kty", json_string(nameof_key_type(item.type)));

    /* kid */
    if (item.key.get_kid_string().size()) {
        json_object_set_new(json_item, "kid", json_string(item.key.get_kid()));
    }

    /* use */
    if (crypto_use_t::use_sig == item.key.get_use()) {
        json_object_set_new(json_item, "use", json_string("sig"));
    }
    if (crypto_use_t::use_enc == item.key.get_use()) {
        json_object_set_new(json_item, "use", json_string("enc"));
    }

    if (item.key.get_alg_string().size()) {
        json_object_set_new(json_item, "alg", json_string(item.key.get_alg()));
    }

    std::string curve_name;

    if (kindof_ecc(item.type)) {
        advisor->nameof_ec_curve(item.key.get_pkey(), curve_name);
    }

    /* param */
    if (crypto_kty_t::kty_oct == item.type) {
        json_object_set_new(json_item, "k", json_string(base64_encode(item.priv, base64_encoding_t::base64url_encoding).c_str()));
    } else if (crypto_kty_t::kty_rsa == item.type) {
        json_object_set_new(json_item, "n", json_string(base64_encode(item.pub1, base64_encoding_t::base64url_encoding).c_str()));
        json_object_set_new(json_item, "e", json_string(base64_encode(item.pub2, base64_encoding_t::base64url_encoding).c_str()));
        if (flag) {
            json_object_set_new(json_item, "d", json_string(base64_encode(item.priv, base64_encoding_t::base64url_encoding).c_str()));
        }
    } else if (crypto_kty_t::kty_ec == item.type) {
        json_object_set_new(json_item, "crv", json_string(curve_name.c_str()));
        json_object_set_new(json_item, "x", json_string(base64_encode(item.pub1, base64_encoding_t::base64url_encoding).c_str()));
        json_object_set_new(json_item, "y", json_string(base64_encode(item.pub2, base64_encoding_t::base64url_encoding).c_str()));
        if (flag) {
            json_object_set_new(json_item, "d", json_string(base64_encode(item.priv, base64_encoding_t::base64url_encoding).c_str()));
        }
    } else if (crypto_kty_t::kty_okp == item.type) {
        json_object_set_new(json_item, "crv", json_string(curve_name.c_str()));
        json_object_set_new(json_item, "x", json_string(base64_encode(item.pub1, base64_encoding_t::base64url_encoding).c_str()));
        if (flag) {
            json_object_set_new(json_item, "d", json_string(base64_encode(item.priv, base64_encoding_t::base64url_encoding).c_str()));
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
                json_t* json_keys = json_array();
                if (json_keys) {
                    for (const auto& item : mapper.items) {
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
        mapper->items.push_back(item);
    }
    __finally2 {
        // do nothing
    }
    // do not return
}

return_t json_web_key::write(crypto_key* crypto_key, char* buf, size_t* buflen, int flags) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == crypto_key || nullptr == buflen) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        size_t size_request = *buflen;
        json_mapper_t mapper;

        mapper.flag = flags;
        crypto_key->for_each(json_writer, &mapper);

        std::string buffer;
        auto lambda = [](char* data, std::string& buffer) -> void { buffer = data; };
        jwk_serialize_t<std::string>(mapper, lambda, buffer);

        *buflen = buffer.size() + 1;
        if (buffer.size() + 1 > size_request) {
            ret = errorcode_t::insufficient_buffer;
            __leave2;
        } else {
            if (buf) {
                memcpy(buf, buffer.c_str(), buffer.size());
                *(buf + buffer.size()) = 0;
            } else {
                ret = errorcode_t::invalid_parameter;
                __leave2;
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t json_web_key::write(crypto_key* crypto_key, std::string& buf, int flags) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == crypto_key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        buf.clear();

        json_mapper_t mapper;

        mapper.flag = flags;
        crypto_key->for_each(json_writer, &mapper);

        auto lambda = [](char* data, std::string& buffer) -> void { buffer = data; };
        jwk_serialize_t<std::string>(mapper, lambda, buf);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t json_web_key::write(crypto_key* crypto_key, stream_t* buf, int flags) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == crypto_key || nullptr == buf) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        buf->clear();

        json_mapper_t mapper;

        mapper.flag = flags;
        crypto_key->for_each(json_writer, &mapper);

        auto lambda = [](char* data, stream_t*& stream) -> void { stream->printf("%s", data); };
        jwk_serialize_t<stream_t*>(mapper, lambda, buf);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t json_web_key::load_file(crypto_key* crypto_key, const char* file, int flags) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == crypto_key || nullptr == file) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        std::string buffer;
        std::ifstream fs(file);
        if (fs.is_open()) {
            std::getline(fs, buffer, (char)fs.eof());

            ret = load(crypto_key, buffer.c_str(), flags);
            if (errorcode_t::success != ret) {
                __leave2;
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t json_web_key::write_file(crypto_key* crypto_key, const char* file, int flags) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == crypto_key || nullptr == file) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        file_stream fs;
        ret = fs.open(file, filestream_flag_t::open_write);
        if (errorcode_t::success == ret) {
            fs.truncate(0);

            ret = write(crypto_key, &fs, flags);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
