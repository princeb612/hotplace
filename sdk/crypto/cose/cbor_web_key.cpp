/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 8152 CBOR Object Signing and Encryption (COSE)
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/base16.hpp>
#include <hotplace/sdk/base/basic/base64.hpp>
#include <hotplace/sdk/base/basic/variant.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/crypto_keychain.hpp>
#include <hotplace/sdk/crypto/basic/evp_key.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>
#include <hotplace/sdk/crypto/cose/cbor_web_key.hpp>
#include <hotplace/sdk/io/stream/file_stream.hpp>

namespace hotplace {
namespace crypto {

cbor_web_key::cbor_web_key() : crypto_keychain() {}

cbor_web_key::~cbor_web_key() {}

return_t cbor_web_key::load(crypto_key* cryptokey, keyflag_t mode, const char* buffer, size_t size, const keydesc& desc, int flag) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == cryptokey || nullptr == buffer) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (key_ownspec == mode) {
            ret = load(cryptokey, (byte_t*)buffer, size, flag);  // binary
        } else {
            ret = crypto_keychain::load(cryptokey, mode, buffer, size, desc, flag);
        }
    }
    __finally2 {}
    return ret;
}

return_t cbor_web_key::load_b16(crypto_key* cryptokey, const std::string& buf, int flag) { return load_b16(cryptokey, buf.c_str(), buf.size(), flag); }

return_t cbor_web_key::load_b16(crypto_key* cryptokey, const char* buffer, size_t size, int flag) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == buffer) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        binary_t bin = std::move(base16_decode(buffer, size));
        ret = load(cryptokey, &bin[0], bin.size(), flag);
    }
    __finally2 {}
    return ret;
}

typedef struct _cose_object_key {
    int type;
    int curve;
    std::string kid;
    std::map<int, binary_t> attrib;

    _cose_object_key() : type(0), curve(0) {}
} cose_key_object;

return_t cbor_web_key::load(crypto_key* cryptokey, const byte_t* buffer, size_t size, int flag) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == cryptokey || nullptr == buffer) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cbor_reader reader;
        cbor_reader_context_t* handle = nullptr;
        cbor_object* root = nullptr;

        reader.open(&handle);
        reader.parse(handle, buffer, size);
        ret = reader.publish(handle, &root);
        reader.close(handle);

        ret = load(cryptokey, root);

        root->release();
    }
    __finally2 {}
    return ret;
}

return_t cbor_web_key::load(crypto_key* cryptokey, const binary_t& buffer, int flag) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = load(cryptokey, &buffer[0], buffer.size(), flag);
    }
    __finally2 {}
    return ret;
}

return_t cbor_web_key::load(crypto_key* key, cbor_object* root, int flag) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        if (nullptr == key || nullptr == root) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (cbor_type_t::cbor_type_array == root->type()) {
            const std::list<cbor_object*>& keys = ((cbor_array*)root)->accessor();
            for (cbor_object* child : keys) {
                do_load(key, child, flag);
            }
        } else if (cbor_type_t::cbor_type_map == root->type()) {
            do_load(key, root, flag);
        }
    }
    __finally2 {}
    return ret;
}

return_t cbor_web_key::do_load(crypto_key* cryptokey, cbor_object* object, int flag) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        if (nullptr == cryptokey || nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (cbor_type_t::cbor_type_map == object->type()) {
            cose_key_object keyobj;
            const std::list<cbor_pair*>& key_contents = ((cbor_map*)object)->accessor();
            for (cbor_pair* pair : key_contents) {
                cbor_data* lhs = (cbor_data*)pair->left();
                cbor_data* rhs = (cbor_data*)pair->right();
                // (nullptr != lhs) && (nullptr != rhs)
                if ((lhs->type() == rhs->type()) && (cbor_type_t::cbor_type_data == lhs->type())) {
                    int label = lhs->data().to_int();
                    const variant_t& vt_rhs = rhs->data().content();
                    if (cose_key_lable_t::cose_lable_kid == label) {  // 2
                        rhs->data().to_string(keyobj.kid);
                    } else if (cose_key_lable_t::cose_lable_kty == label) {  // 1
                        keyobj.type = rhs->data().to_int();
                    } else if (-1 == label) {  // ec2 curve, symmetric k
                        if (TYPE_BINARY == vt_rhs.type) {
                            // symm
                            binary_t bin;
                            rhs->data().to_binary(bin);
                            keyobj.attrib.insert(std::make_pair(label, bin));
                        } else {
                            // curve if okp, ec2
                            keyobj.curve = rhs->data().to_int();
                        }
                    } else if (label < -1) {  // ec2 (-2 x, -3 y, -4 d), rsa (-1 n, -2 e, -3 d, ..., -12 ti)
                        binary_t bin;
                        rhs->data().to_binary(bin);
                        keyobj.attrib.insert(std::make_pair(label, bin));
                    }
                }
            }
            t_maphint<int, binary_t> hint_key(keyobj.attrib);
            keydesc desc(keyobj.kid);
            if (cose_kty_t::cose_kty_okp == keyobj.type || cose_kty_t::cose_kty_ec2 == keyobj.type) {  // 1, 2
                uint32 nid = advisor->curveof((cose_ec_curve_t)keyobj.curve);
                binary_t x;
                binary_t y;
                binary_t d;
                hint_key.find(cose_key_lable_t::cose_ec_x, &x);  // -2
                hint_key.find(cose_key_lable_t::cose_ec_y, &y);  // -3
                hint_key.find(cose_key_lable_t::cose_ec_d, &d);  // -4
                add_ec2(cryptokey, nid, x, y, d, desc);
            } else if (cose_kty_t::cose_kty_rsa == keyobj.type) {  // 3
                binary_t n;
                binary_t e;
                binary_t d;
                hint_key.find(cose_key_lable_t::cose_rsa_n, &n);  // -1
                hint_key.find(cose_key_lable_t::cose_rsa_e, &e);  // -2
                hint_key.find(cose_key_lable_t::cose_rsa_d, &d);  // -3
                add_rsa(cryptokey, nid_rsa, n, e, d, desc);
            } else if (cose_kty_t::cose_kty_symm == keyobj.type) {  // 4
                binary_t k;
                hint_key.find(cose_key_lable_t::cose_symm_k, &k);  // -1
                add_oct(cryptokey, k, desc);
            }
        }
    }
    __finally2 {}
    return ret;
}

return_t cbor_web_key::write(crypto_key* cryptokey, keyflag_t mode, stream_t* stream, int flag) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (key_ownspec == mode) {
            ret = write(cryptokey, stream, flag);
        } else {
            ret = crypto_keychain::write(cryptokey, mode, stream, flag);
        }
    }
    __finally2 {}
    return ret;
}

return_t cbor_web_key::write(crypto_key* cryptokey, stream_t* stream, int flag) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == cryptokey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        binary_t cbor;
        ret = write(cryptokey, cbor, flag);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        stream->write(&cbor[0], cbor.size());  // binary
    }
    __finally2 {}
    return ret;
}

typedef struct _cose_mapper_t {
    cbor_array* root;

    _cose_mapper_t() : root(nullptr) {}
} cose_mapper_t;

void cwk_writer(crypto_key_object* key, void* param) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        if (nullptr == param) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cose_mapper_t* mapper = (cose_mapper_t*)param;
        cbor_array* root = mapper->root;
        if (nullptr == root) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        crypto_kty_t kty;
        binary_t pub1;
        binary_t pub2;
        binary_t priv;

        auto pkey = key->get_pkey();
        auto hint = advisor->hintof_curve_eckey(pkey);

        if (hint && (CURVE_SUPPORT_COSE)) {
            // do nothing
        } else {
            __leave2;
        }

        // RFC 8152
        // 13.1.1.  Double Coordinate Curves
        // 13.2.  Octet Key Pair
        // Leading zero octets MUST be preserved.
        ret = crypto_key::get_key(pkey, 1, kty, pub1, pub2, priv, true);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        bool skip = false;
        switch (kty) {
            case kty_oct:
            case kty_rsa:
            case kty_ec:
            case kty_okp:
                break;
            default:
                skip = true;
                break;
        }
        if (skip) {
            __leave2;
        }

        std::string kid = key->get_desc().get_kid_str();

        cbor_map* keynode = nullptr;
        __try_new_catch(keynode, new cbor_map(), ret, __leave2);

        cose_kty_t cose_kty = advisor->ktyof(kty);
        *keynode << new cbor_pair(cose_key_lable_t::cose_lable_kty, new cbor_data(cose_kty));  // 1
        if (kid.size()) {
            *keynode << new cbor_pair(cose_key_lable_t::cose_lable_kid, new cbor_data(str2bin(kid)));  // 2
        }

        if (crypto_kty_t::kty_ec == kty || crypto_kty_t::kty_okp == kty) {
            uint32 nid = 0;
            cose_ec_curve_t cose_curve = cose_ec_curve_t::cose_ec_unknown;

            nidof_evp_pkey(key->get_pkey(), nid);
            cose_curve = advisor->curveof(nid);

            *keynode << new cbor_pair(cose_key_lable_t::cose_ec_crv, new cbor_data(cose_curve))  // -1
                     << new cbor_pair(cose_key_lable_t::cose_ec_x, new cbor_data(pub1));         // -2

            if (crypto_kty_t::kty_ec == kty) {
                *keynode << new cbor_pair(cose_key_lable_t::cose_ec_y, new cbor_data(pub2));  // -3
            }
            if (priv.size()) {
                *keynode << new cbor_pair(cose_key_lable_t::cose_ec_d, new cbor_data(priv));  // -4
            }
        } else if (crypto_kty_t::kty_oct == kty) {
            *keynode << new cbor_pair(cose_key_lable_t::cose_symm_k, new cbor_data(priv));  // -1
        } else if (crypto_kty_t::kty_rsa == kty) {
            *keynode << new cbor_pair(cose_key_lable_t::cose_rsa_n, new cbor_data(pub1))   // -1
                     << new cbor_pair(cose_key_lable_t::cose_rsa_e, new cbor_data(pub2));  // -2
            if (priv.size()) {
                *keynode << new cbor_pair(cose_key_lable_t::cose_rsa_d, new cbor_data(priv));  // -3
            }
        }

        *root << keynode;
    }
    __finally2 {}
}

return_t cbor_web_key::write(crypto_key* cryptokey, std::string& buf, int flag) {
    return_t ret = errorcode_t::success;

    __try2 {
        binary_t cbor;
        ret = write(cryptokey, cbor, flag);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        base16_encode(cbor, buf);
    }
    __finally2 {}
    return ret;
}

return_t cbor_web_key::write(crypto_key* cryptokey, binary_t& cbor, int flag) {
    return_t ret = errorcode_t::success;
    cbor_object* root = nullptr;

    __try2 {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = write(cryptokey, &root, flag);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        cbor_publisher publisher;
        ret = publisher.publish(root, &cbor);
    }
    __finally2 {
        if (root) {
            root->release();
        }
    }
    return ret;
}

return_t cbor_web_key::write(crypto_key* cryptokey, cbor_object** root, int flag) {
    return_t ret = errorcode_t::success;
    cbor_array* cbor_root = nullptr;

    __try2 {
        if (nullptr == cryptokey || nullptr == root) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        __try_new_catch(cbor_root, new cbor_array(), ret, __leave2);

        cose_mapper_t mapper;
        mapper.root = cbor_root;

        cryptokey->for_each(cwk_writer, &mapper);

        *root = cbor_root;
    }
    __finally2 {}
    return ret;
}

return_t cbor_web_key::diagnose(crypto_key* cryptokey, stream_t* stream, int flag) {
    return_t ret = errorcode_t::success;
    cbor_object* root = nullptr;

    __try2 {
        if (nullptr == cryptokey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        stream->clear();

        ret = write(cryptokey, &root, flag);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        cbor_publisher publisher;

        publisher.publish(root, stream);
    }
    __finally2 {
        if (root) {
            root->release();
        }
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
