/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 8152 CBOR Object Signing and Encryption (COSE)
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/crypto_keychain.hpp>
#include <sdk/crypto/basic/openssl_crypt.hpp>
#include <sdk/crypto/basic/openssl_hash.hpp>
#include <sdk/crypto/basic/openssl_sign.hpp>
#include <sdk/crypto/cose/cbor_object_signing.hpp>
#include <sdk/crypto/cose/cose_composer.hpp>

namespace hotplace {
namespace crypto {

#define TYPE_STATIC_KEY (TYPE_USER)
#define TYPE_COUNTER_SIG (vartype_t)(TYPE_USER + 1)

cose_data::cose_data() : _layer(nullptr) {}

cose_data::~cose_data() { clear(); }

cose_data& cose_data::set_owner(cose_recipient* layer) {
    _layer = layer;
    return *this;
}

cose_recipient* cose_data::get_owner() { return _layer; }

cose_data& cose_data::add_bool(int key, bool value) {
    variant var;
    _data_map.insert(std::make_pair(key, std::move(var.set_bool(value))));
    _order.push_back(key);
    return *this;
}

cose_data& cose_data::add(int key, int32 value) {
    variant var;
    _data_map.insert(std::make_pair(key, std::move(var.set_int32(value))));
    _order.push_back(key);
    return *this;
}

cose_data& cose_data::add(int key, const char* value) {
    if (value) {
        variant var;
        _data_map.insert(std::make_pair(key, std::move(var.set_bstr_new((unsigned char*)value, strlen(value)))));
        _order.push_back(key);
    }
    return *this;
}

cose_data& cose_data::add(int key, const unsigned char* value, size_t size) {
    variant var;
    _data_map.insert(std::make_pair(key, std::move(var.set_bstr_new(value, size))));
    _order.push_back(key);
    return *this;
}

cose_data& cose_data::replace(int key, const unsigned char* value, size_t size) {
    cose_variantmap_t::iterator iter = _data_map.find(key);
    if (_data_map.end() != iter) {
        variant var;
        var.set_bstr_new(value, size);
        iter->second = std::move(var);
    } else {
        variant var;
        _data_map.insert(std::make_pair(key, std::move(var.set_bstr_new(value, size))));
        _order.push_back(key);
    }
    return *this;
}

cose_data& cose_data::add(int key, std::string& value) { return add(key, (unsigned char*)value.c_str(), value.size()); }

cose_data& cose_data::add(int key, const std::string& value) { return add(key, (unsigned char*)value.c_str(), value.size()); }

cose_data& cose_data::add(int key, binary_t& value) { return add(key, &value[0], value.size()); }

cose_data& cose_data::add(int key, const binary_t& value) { return add(key, &value[0], value.size()); }

cose_data& cose_data::replace(int key, const binary_t& value) { return replace(key, &value[0], value.size()); }

cose_data& cose_data::add(int key, uint16 curve, const binary_t& x, const binary_t& y) {
    cose_key* k = nullptr;
    return_t ret = errorcode_t::success;
    __try2 {
        __try_new_catch(k, new cose_key(), ret, __leave2);

        k->set(&get_owner()->get_static_key(), curve, x, y);
        add(key, TYPE_STATIC_KEY, k);

        _keys.push_back(k);
    }
    __finally2 {
        // do nothing
    }
    return *this;
}

cose_data& cose_data::add(int key, uint16 curve, const binary_t& x, const binary_t& y, std::list<int>& order) {
    cose_key* k = nullptr;
    return_t ret = errorcode_t::success;
    __try2 {
        __try_new_catch(k, new cose_key(), ret, __leave2);

        k->set(&get_owner()->get_static_key(), curve, x, y);
        k->set(order);
        add(key, TYPE_STATIC_KEY, k);

        _keys.push_back(k);
    }
    __finally2 {
        // do nothing
    }
    return *this;
}

cose_data& cose_data::add(int key, uint16 curve, const binary_t& x, bool ysign) {
    cose_key* k = nullptr;
    return_t ret = errorcode_t::success;
    __try2 {
        __try_new_catch(k, new cose_key(), ret, __leave2);

        k->set(&get_owner()->get_static_key(), curve, x, ysign);
        add(key, TYPE_STATIC_KEY, k);

        _keys.push_back(k);
    }
    __finally2 {
        // do nothing
    }
    return *this;
}

cose_data& cose_data::add(int key, uint16 curve, const binary_t& x, bool ysign, std::list<int>& order) {
    cose_key* k = nullptr;
    return_t ret = errorcode_t::success;
    __try2 {
        __try_new_catch(k, new cose_key(), ret, __leave2);

        k->set(&get_owner()->get_static_key(), curve, x, ysign);
        k->set(order);
        add(key, TYPE_STATIC_KEY, k);

        _keys.push_back(k);
    }
    __finally2 {
        // do nothing
    }
    return *this;
}

cose_data& cose_data::add(cose_alg_t alg, const char* kid, const binary_t& signature) {
    cose_countersign* countersign = nullptr;
    return_t ret = errorcode_t::success;

    __try2 {
        __try_new_catch(countersign, new cose_countersign, ret, __leave2);
        countersign->set_upperlayer(get_owner());
        countersign->set_property(cose_property_t::cose_property_countersign);

        countersign->get_protected().add(cose_key_t::cose_alg, alg);
        if (kid) {
            countersign->get_unprotected().add(cose_key_t::cose_kid, kid);
        }
        countersign->get_signature().set(signature);

        add(countersign);
    }
    __finally2 {
        // do nothing
    }
    return *this;
}

cose_data& cose_data::add(cose_recipient* countersign) {
    return_t ret = errorcode_t::success;

    __try2 {
        cose_countersigns* countersigns = get_owner()->get_countersigns1();
        cose_variantmap_t::iterator iter = _data_map.find(cose_key_t::cose_counter_sig);
        if (_data_map.end() == iter) {
            add(cose_key_t::cose_counter_sig, TYPE_COUNTER_SIG, countersigns);
        }
        countersigns->add(countersign);
    }
    __finally2 {
        // do nothing
    }
    return *this;
}

cose_data& cose_data::add(int key, vartype_t vty, void* p) {
    if (p) {
        variant vt;
        _data_map.insert(std::make_pair(key, std::move(vt.set_user_type(vty, p))));
        _order.push_back(key);
    }
    return *this;
}

cose_data& cose_data::add(int key, variant& value) {
    _data_map.insert(std::make_pair(key, value));
    _order.push_back(key);
    return *this;
}

cose_data& cose_data::set(const binary_t& bin) {
    _payload = bin;
    return *this;
}

cose_data& cose_data::set(const std::string& value) {
    _payload = std::move(str2bin(value));
    return *this;
}

cose_data& cose_data::set_b16(std::string const value) {
    _payload = std::move(base16_decode(value));
    return *this;
}

cose_data& cose_data::set_b16(const char* value) {
    if (value) {
        _payload = std::move(base16_decode(value, strlen(value)));
    }
    return *this;
}

cose_data& cose_data::clear() {
    _data_map.clear();
    _order.clear();
    _payload.clear();
    for (cose_key* key : _keys) {
        delete key;
    }
    _keys.clear();
    return *this;
}

bool cose_data::exist(int key) {
    bool ret_value = false;
    return_t ret = errorcode_t::success;

    std::map<int, variant>::iterator iter = _data_map.find(key);
    if (_data_map.end() != iter) {
        ret_value = true;
    }
    return ret_value;
}

return_t cose_data::finditem(int key, int& value) {
    return_t ret = errorcode_t::success;

    std::map<int, variant>::iterator iter = _data_map.find(key);
    if (_data_map.end() == iter) {
        ret = errorcode_t::not_found;
    } else {
        value = iter->second.to_int();
    }
    return ret;
}

return_t cose_data::finditem(int key, std::string& value) {
    return_t ret = errorcode_t::success;

    std::map<int, variant>::iterator iter = _data_map.find(key);
    if (_data_map.end() == iter) {
        ret = errorcode_t::not_found;
    } else {
        iter->second.to_string(value);
    }
    return ret;
}

return_t cose_data::finditem(int key, binary_t& value) {
    return_t ret = errorcode_t::success;
    variant vt;

    std::map<int, variant>::iterator iter = _data_map.find(key);
    if (_data_map.end() == iter) {
        ret = errorcode_t::not_found;
    } else {
        iter->second.to_binary(value);
    }
    return ret;
}

return_t cose_data::build_protected(cbor_data** object) {
    return_t ret = errorcode_t::success;
    cbor_map* part_protected = nullptr;

    __try2 {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (_payload.size()) {
            *object = new cbor_data(_payload);
        } else {
            if (_data_map.size()) {
                __try_new_catch(part_protected, new cbor_map(), ret, __leave2);

                for (const auto& key : _order) {
                    cose_variantmap_t::iterator map_iter = _data_map.find(key);
                    variant value = map_iter->second;
                    *part_protected << new cbor_pair(new cbor_data(key), new cbor_data(std::move(value)));
                }

                cbor_publisher publisher;
                publisher.publish(part_protected, &_payload);

                *object = new cbor_data(_payload);
            } else {
                *object = new cbor_data(binary_t());
            }
        }
    }
    __finally2 {
        if (part_protected) {
            part_protected->release();
        }
    }
    return ret;
}

return_t cose_data::build_protected(cbor_data** object, cose_variantmap_t& unsent) {
    return_t ret = errorcode_t::success;
    cbor_map* part_protected = nullptr;

    __try2 {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (_payload.size()) {
            *object = new cbor_data(_payload);
        } else {
            if (_data_map.size()) {
                __try_new_catch(part_protected, new cbor_map(), ret, __leave2);

                for (const auto& key : _order) {
                    cose_variantmap_t::iterator unsent_iter = unsent.find(key);
                    if (unsent.end() != unsent_iter) {
                        continue;
                    }

                    cose_variantmap_t::iterator map_iter = _data_map.find(key);
                    variant value = map_iter->second;
                    *part_protected << new cbor_pair(new cbor_data(key), new cbor_data(std::move(value)));
                }

                cbor_publisher publisher;
                publisher.publish(part_protected, &_payload);

                *object = new cbor_data(_payload);
            } else {
                *object = new cbor_data(binary_t());
            }
        }
    }
    __finally2 {
        if (part_protected) {
            part_protected->release();
        }
    }
    return ret;
}

return_t cose_data::build_unprotected(cbor_map** object) {
    return_t ret = errorcode_t::success;
    cbor_map* part_unprotected = nullptr;

    __try2 {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        __try_new_catch(part_unprotected, new cbor_map(), ret, __leave2);

        for (const auto& key : _order) {
            cose_variantmap_t::iterator map_iter = _data_map.find(key);
            variant value = map_iter->second;
            const variant_t& vt = value.content();

            if (TYPE_STATIC_KEY == vt.type) {
                cose_key* k = (cose_key*)vt.data.p;
                *part_unprotected << new cbor_pair(key, k->cbor());
            } else if (TYPE_COUNTER_SIG == vt.type) {
                cose_countersigns* signs = get_owner()->get_countersigns1();
                *part_unprotected << new cbor_pair(cose_key_t::cose_counter_sig, signs->cbor());
            } else {
                *part_unprotected << new cbor_pair(new cbor_data(key), new cbor_data(value));
            }
        }

        *object = part_unprotected;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cose_data::build_unprotected(cbor_map** object, cose_variantmap_t& unsent) {
    return_t ret = errorcode_t::success;
    cbor_map* part_unprotected = nullptr;

    __try2 {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        __try_new_catch(part_unprotected, new cbor_map(), ret, __leave2);

        for (const auto& key : _order) {
            cose_variantmap_t::iterator unsent_iter = unsent.find(key);
            if (unsent.end() != unsent_iter) {
                continue;
            }

            cose_variantmap_t::iterator map_iter = _data_map.find(key);
            variant value = map_iter->second;
            const variant_t& vt = value.content();

            if (TYPE_STATIC_KEY == vt.type) {
                cose_key* k = (cose_key*)vt.data.p;
                *part_unprotected << new cbor_pair(key, k->cbor());
            } else if (TYPE_COUNTER_SIG == vt.type) {
                cose_recipient* sign = (cose_recipient*)vt.data.p;
                *part_unprotected << new cbor_pair(cose_key_t::cose_counter_sig, sign->cbor());
            } else {
                *part_unprotected << new cbor_pair(new cbor_data(key), new cbor_data(value));
            }
        }

        *object = part_unprotected;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cose_data::build_data(cbor_data** object) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        __try_new_catch(*object, new cbor_data(_payload), ret, __leave2);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cose_data::parse_protected(cbor_data* object) {
    return_t ret = errorcode_t::success;
    cbor_object* root = nullptr;

    __try2 {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        object->data().to_binary(_payload);

        if (0 == _payload.size()) {
            __leave2;
        }

        ret = cbor_parse(&root, _payload);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        cbor_map* datamap = cbor_typeof<cbor_map>(root, cbor_type_t::cbor_type_map);
        if (nullptr == datamap) {
            ret = errorcode_t::bad_format;
            __leave2;
        }

        ret = parse(datamap);
    }
    __finally2 {
        if (root) {
            root->release();
        }
    }
    return ret;
}

return_t cose_data::parse_unprotected(cbor_map* object) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = parse(object);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cose_data::parse_payload(cbor_data* object) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        object->data().to_binary(_payload);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cose_data::parse(cbor_map* object) {
    return_t ret = errorcode_t::success;
    return_t check = errorcode_t::success;

    __try2 {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        size_t size_map = object->size();
        for (size_t i = 0; i < size_map; i++) {
            cbor_pair* pair = (*object)[i];

            cbor_data* pair_key = pair->left();
            int keyid = 0;
            keyid = pair_key->data().to_int();

            cbor_object* pair_value = pair->right();

            cbor_data* data = cbor_typeof<cbor_data>(pair_value, cbor_type_t::cbor_type_data);
            if (data) {
                add(keyid, data->data());
                continue;
            }

            cbor_simple* simple = cbor_typeof<cbor_simple>(pair_value, cbor_type_t::cbor_type_simple);
            if (simple) {
                cbor_simple_t simple_type = simple->simple_type();
                switch (simple_type) {
                    case cbor_simple_true:
                        add_bool(keyid, true);
                        break;
                    case cbor_simple_false:
                        add_bool(keyid, false);
                        break;
                    default:
                        break;
                }
                continue;
            }

            cbor_map* map = cbor_typeof<cbor_map>(pair_value, cbor_type_t::cbor_type_map);
            if (map) {
                parse_static_key(map, keyid);
                continue;
            }

            cbor_array* array = cbor_typeof<cbor_array>(pair_value, cbor_type_t::cbor_type_array);
            if (array) {
                switch (keyid) {
                    case cose_counter_sig:  // (7)
                    {
                        cbor_data* countersig_protected = cbor_typeof<cbor_data>((*array)[0], cbor_type_t::cbor_type_data);
                        if (countersig_protected) {
                            parse_counter_signs(array, keyid);
                        } else {
                            cbor_array* countersigns = cbor_typeof<cbor_array>((*array)[0], cbor_type_t::cbor_type_array);
                            if (countersigns) {
                                for (size_t size = 0; size < countersigns->size(); size++) {
                                    cbor_array* countersign = cbor_typeof<cbor_array>((*array)[size], cbor_type_t::cbor_type_array);
                                    parse_counter_signs(countersign, keyid);
                                }
                            }
                        }
                    } break;
                    case cose_crit:  // (2)
                    default:
                        break;
                }
                continue;
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cose_data::parse_static_key(cbor_map* object, int keyid) {
    return_t ret = errorcode_t::success;
    return_t check = errorcode_t::success;

    __try2 {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cbor_map_hint<int, cbor_map_int_binder<int>> hint(object);
        cose_orderlist_t order;
        uint16 kty = 0;
        uint16 curve = 0;
        binary_t bin_x;
        binary_t bin_y;

        cbor_object* cbor_curve = nullptr;
        cbor_object* cbor_x = nullptr;
        cbor_object* cbor_y = nullptr;

        hint.find(cose_key_lable_t::cose_ec_crv, &cbor_curve);
        hint.find(cose_key_lable_t::cose_ec_x, &cbor_x);
        hint.find(cose_key_lable_t::cose_ec_y, &cbor_y);
        hint.get_order(order);

        if (cbor_curve && cbor_x) {
            cbor_data* cbor_data_curve = cbor_typeof<cbor_data>(cbor_curve, cbor_type_t::cbor_type_data);
            cbor_data* cbor_data_x = cbor_typeof<cbor_data>(cbor_x, cbor_type_t::cbor_type_data);
            cbor_data* cbor_data_y = cbor_typeof<cbor_data>(cbor_y, cbor_type_t::cbor_type_data);
            cbor_simple* cbor_simple_y = cbor_typeof<cbor_simple>(cbor_y, cbor_type_t::cbor_type_simple);

            curve = cbor_data_curve->data().to_int();
            cbor_data_x->data().to_binary(bin_x);

            switch (curve) {
                case cose_ec_p256:
                case cose_ec_p384:
                case cose_ec_p521:
                    if (cbor_data_y) {
                        cbor_data_y->data().to_binary(bin_y);
                        add(keyid, curve, bin_x, bin_y, order);
                    } else if (cbor_simple_y) {
                        add(keyid, curve, bin_x, cbor_simple_true == cbor_simple_y->simple_type(), order);
                    } else {
                        ret = errorcode_t::bad_format;
                    }
                    break;
                case cose_ec_x25519:
                case cose_ec_x448:
                case cose_ec_ed25519:
                case cose_ec_ed448:
                    add(keyid, curve, bin_x, bin_y, order);
                    break;
            }

            cbor_curve->release();
            cbor_x->release();
        }

        if (cbor_y) {
            cbor_y->release();
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cose_data::parse_counter_signs(cbor_array* object, int keyid) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (object->size() == 3) {
            cbor_data* countersig_protected = cbor_typeof<cbor_data>((*object)[0], cbor_type_t::cbor_type_data);
            cbor_map* countersig_unprotected = cbor_typeof<cbor_map>((*object)[1], cbor_type_t::cbor_type_map);
            cbor_data* countersig_signature = cbor_typeof<cbor_data>((*object)[2], cbor_type_t::cbor_type_data);
            if (countersig_protected && countersig_unprotected && countersig_signature) {
                cose_countersign* countersign = nullptr;
                __try_new_catch_only(countersign, new cose_countersign);

                countersign->set_upperlayer(get_owner());
                countersign->set_composer(get_owner()->get_composer());
                countersign->set_property(cose_property_t::cose_property_countersign);

                countersign->get_protected().set(countersig_protected);
                countersign->get_unprotected().set(countersig_unprotected);  // keep order
                countersign->get_signature().set(countersig_signature);

                add(countersign);
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

bool cose_data::empty_binary() { return 0 == _payload.size(); }

size_t cose_data::size_binary() { return _payload.size(); }

void cose_data::get_binary(binary_t& bin) { bin = _payload; }

}  // namespace crypto
}  // namespace hotplace
