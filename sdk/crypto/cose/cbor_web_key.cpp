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

#include <sdk/base/basic/base16.hpp>
#include <sdk/base/basic/base64.hpp>
#include <sdk/base/basic/variant.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/crypto_keychain.hpp>
#include <sdk/crypto/basic/evp_key.hpp>
#include <sdk/crypto/basic/openssl_sdk.hpp>
#include <sdk/crypto/cose/cbor_web_key.hpp>
#include <sdk/io/basic/json.hpp>
#include <sdk/io/cbor/cbor_array.hpp>
#include <sdk/io/cbor/cbor_data.hpp>
#include <sdk/io/cbor/cbor_map.hpp>
#include <sdk/io/cbor/cbor_publisher.hpp>
#include <sdk/io/cbor/cbor_reader.hpp>
#include <sdk/io/stream/file_stream.hpp>

namespace hotplace {
using namespace io;
namespace crypto {

cbor_web_key::cbor_web_key() : crypto_keychain() {
    // do nothing
}

cbor_web_key::~cbor_web_key() {
    // do nothing
}

return_t cbor_web_key::load(crypto_key* crypto_key, const char* buffer, int flags) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == crypto_key || nullptr == buffer) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        binary_t bin;
        bin = base16_decode(buffer);

        ret = load(crypto_key, &bin[0], bin.size(), flags);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_web_key::load(crypto_key* crypto_key, const std::string& buf, int flags) { return load(crypto_key, buf.c_str(), flags); }

typedef struct _cose_object_key {
    int type;
    int curve;
    std::string kid;
    std::map<int, binary_t> attrib;

    _cose_object_key() : type(0), curve(0) {
        // do nothing
    }
} cose_key_object;

return_t cbor_web_key::load(crypto_key* crypto_key, const byte_t* buffer, size_t size, int flags) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == buffer) {
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

        ret = load(crypto_key, root);

        root->release();
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_web_key::load(crypto_key* crypto_key, const binary_t& buffer, int flags) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == crypto_key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = load(crypto_key, &buffer[0], buffer.size(), flags);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_web_key::load(crypto_key* key, cbor_object* root, int flags) {
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
                do_load(key, child, flags);
            }
        } else if (cbor_type_t::cbor_type_map == root->type()) {
            do_load(key, root, flags);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_web_key::do_load(crypto_key* crypto_key, cbor_object* object, int flags) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        if (nullptr == crypto_key || nullptr == object) {
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
            if (cose_kty_t::cose_kty_okp == keyobj.type || cose_kty_t::cose_kty_ec2 == keyobj.type) {  // 1, 2
                uint32 nid = advisor->curveof((cose_ec_curve_t)keyobj.curve);
                binary_t x;
                binary_t y;
                binary_t d;
                hint_key.find(cose_key_lable_t::cose_ec_x, &x);  // -2
                hint_key.find(cose_key_lable_t::cose_ec_y, &y);  // -3
                hint_key.find(cose_key_lable_t::cose_ec_d, &d);  // -4
                add_ec(crypto_key, keyobj.kid.c_str(), nullptr, nid, x, y, d);
            } else if (cose_kty_t::cose_kty_rsa == keyobj.type) {  // 3
                binary_t n;
                binary_t e;
                binary_t d;
                hint_key.find(cose_key_lable_t::cose_rsa_n, &n);  // -1
                hint_key.find(cose_key_lable_t::cose_rsa_e, &e);  // -2
                hint_key.find(cose_key_lable_t::cose_rsa_d, &d);  // -3
                add_rsa(crypto_key, keyobj.kid.c_str(), nullptr, n, e, d);
            } else if (cose_kty_t::cose_kty_symm == keyobj.type) {  // 4
                binary_t k;
                hint_key.find(cose_key_lable_t::cose_symm_k, &k);  // -1
                add_oct(crypto_key, keyobj.kid.c_str(), nullptr, k);
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_web_key::write(crypto_key* crypto_key, char* buf, size_t* buflen, int flags) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == crypto_key || nullptr == buflen) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        binary_t cbor;
        ret = write(crypto_key, cbor, flags);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = base16_encode(cbor, buf, buflen);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

typedef struct _cose_mapper_t {
    cbor_array* root;

    _cose_mapper_t() : root(nullptr) {
        // do nothing
    }
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

        std::string kid = key->get_kid();

        crypto_kty_t kty;
        binary_t pub1;
        binary_t pub2;
        binary_t priv;

        // RFC 8152
        // 13.1.1.  Double Coordinate Curves
        // 13.2.  Octet Key Pair
        // Leading zero octets MUST be preserved.
        ret = crypto_key::get_key(key->get_pkey(), 1, kty, pub1, pub2, priv, true);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        cbor_map* keynode = nullptr;
        __try_new_catch(keynode, new cbor_map(), ret, __leave2);

        cose_kty_t cose_kty = advisor->ktyof(kty);
        *keynode << new cbor_pair(cose_key_lable_t::cose_lable_kty, new cbor_data(cose_kty));  // 1
        if (kid.size()) {
            *keynode << new cbor_pair(cose_key_lable_t::cose_lable_kid, new cbor_data(strtobin(kid)));  // 2
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
    __finally2 {
        // do nothing
    }
}

return_t cbor_web_key::write(crypto_key* crypto_key, std::string& buf, int flags) {
    return_t ret = errorcode_t::success;

    __try2 {
        binary_t cbor;
        ret = write(crypto_key, cbor, flags);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        base16_encode(cbor, buf);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_web_key::write(crypto_key* crypto_key, binary_t& cbor, int flags) {
    return_t ret = errorcode_t::success;
    cbor_object* root = nullptr;

    __try2 {
        if (nullptr == crypto_key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = write(crypto_key, &root, flags);
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

return_t cbor_web_key::write(crypto_key* crypto_key, cbor_object** root, int flags) {
    return_t ret = errorcode_t::success;
    cbor_array* cbor_root = nullptr;

    __try2 {
        if (nullptr == crypto_key || nullptr == root) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        __try_new_catch(cbor_root, new cbor_array(), ret, __leave2);

        cose_mapper_t mapper;
        mapper.root = cbor_root;

        crypto_key->for_each(cwk_writer, &mapper);

        *root = cbor_root;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_web_key::diagnose(crypto_key* crypto_key, stream_t* stream, int flags) {
    return_t ret = errorcode_t::success;
    cbor_object* root = nullptr;

    __try2 {
        if (nullptr == crypto_key || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        stream->clear();

        ret = write(crypto_key, &root, flags);
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

return_t cbor_web_key::load_file(crypto_key* crypto_key, const char* file, int flags) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == crypto_key || nullptr == file) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        file_stream fs;
        ret = fs.open(file);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        fs.begin_mmap();
        ret = load(crypto_key, (byte_t*)fs.data(), fs.size(), flags);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_web_key::write_file(crypto_key* crypto_key, const char* file, int flags) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == crypto_key || nullptr == file) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        file_stream fs;
        ret = fs.open(file, filestream_flag_t::open_write);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        fs.truncate(0);

        binary_t cbor;
        write(crypto_key, cbor, flags);
        fs.write(&cbor[0], cbor.size());
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
