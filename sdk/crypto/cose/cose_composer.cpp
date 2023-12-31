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

#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/crypto_keychain.hpp>
#include <sdk/crypto/basic/openssl_crypt.hpp>
#include <sdk/crypto/basic/openssl_hash.hpp>
#include <sdk/crypto/basic/openssl_sign.hpp>
#include <sdk/crypto/cose/cbor_object_signing.hpp>
#include <sdk/crypto/cose/cose_composer.hpp>

namespace hotplace {
using namespace io;
namespace crypto {

#define TYPE_STATIC_KEY (TYPE_USER)
#define TYPE_COUNTER_SIG (vartype_t)(TYPE_USER + 1)

cose_data::cose_key::cose_key() : _curve(0) {}

void cose_data::cose_key::set(crypto_key* key, uint16 curve, binary_t const& x, binary_t const& y) {
    _curve = curve;
    _x = x;
    _y = y;
    _compressed = false;

    crypto_advisor* advisor = crypto_advisor::get_instance();
    const hint_curve_t* hint = advisor->hintof_curve((cose_ec_curve_t)curve);
    crypto_keychain keychain;
    binary_t d;
    keychain.add_ec(key, nullptr, hint->nid, x, y, d);
}

void cose_data::cose_key::set(crypto_key* key, uint16 curve, binary_t const& x, bool ysign) {
    _curve = curve;
    _x = x;
    _y.clear();
    _ysign = ysign;
    _compressed = true;

    crypto_advisor* advisor = crypto_advisor::get_instance();
    const hint_curve_t* hint = advisor->hintof_curve((cose_ec_curve_t)curve);
    crypto_keychain keychain;
    binary_t d;
    keychain.add_ec(key, nullptr, hint->nid, x, ysign, d);
}

void cose_data::cose_key::set(cose_orderlist_t& order) { _order = order; }

cbor_map* cose_data::cose_key::cbor() {
    cbor_map* object = nullptr;
    __try2 {
        __try_new_catch_only(object, new cbor_map());
        if (nullptr == object) {
            __leave2;
        }

        cose_kty_t kty;
        switch (_curve) {
            case cose_ec_p256:
            case cose_ec_p384:
            case cose_ec_p521:
                kty = cose_kty_t::cose_kty_ec2;
                break;
            default:
                kty = cose_kty_t::cose_kty_okp;
                break;
        }

        if (_order.size()) {
            for (cose_orderlist_t::iterator iter = _order.begin(); iter != _order.end(); iter++) {
                int key = *iter;
                switch (key) {
                    case cose_key_lable_t::cose_lable_kty:
                        *object << new cbor_pair(cose_key_lable_t::cose_lable_kty, new cbor_data(kty));
                        break;
                    case cose_key_lable_t::cose_ec_crv:
                        *object << new cbor_pair(cose_key_lable_t::cose_ec_crv, new cbor_data(_curve));
                        break;
                    case cose_key_lable_t::cose_ec_x:
                        *object << new cbor_pair(cose_key_lable_t::cose_ec_x, new cbor_data(_x));
                        break;
                    case cose_key_lable_t::cose_ec_y:
                        if (_compressed) {
                            *object << new cbor_pair(cose_key_lable_t::cose_ec_y, new cbor_data(_ysign));  // y(-3)
                        } else {
                            *object << new cbor_pair(cose_key_lable_t::cose_ec_y, new cbor_data(_y));  // y(-3)
                        }
                        break;
                    default:
                        break;
                }
            }
        } else {
            *object << new cbor_pair(cose_key_lable_t::cose_lable_kty, new cbor_data(kty))  // kty(1)
                    << new cbor_pair(cose_key_lable_t::cose_ec_crv, new cbor_data(_curve))  // crv(-1)
                    << new cbor_pair(cose_key_lable_t::cose_ec_x, new cbor_data(_x));       // x(-2)

            if (cose_kty_t::cose_kty_ec2 == kty) {
                if (_compressed) {
                    *object << new cbor_pair(cose_key_lable_t::cose_ec_y, new cbor_data(_ysign));  // y(-3)
                } else {
                    *object << new cbor_pair(cose_key_lable_t::cose_ec_y, new cbor_data(_y));  // y(-3)
                }
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return object;
}

cose_data::cose_data() : _layer(nullptr) {}

cose_data::~cose_data() { clear(); }

cose_data& cose_data::set_owner(cose_recipient* layer) {
    _layer = layer;
    return *this;
}

cose_recipient* cose_data::get_owner() { return _layer; }

cose_data& cose_data::add_bool(int key, bool value) {
    variant var;
    _data_map.insert(std::make_pair(key, var.set_bool(value)));
    _order.push_back(key);
    return *this;
}

cose_data& cose_data::add(int key, int32 value) {
    variant var;
    _data_map.insert(std::make_pair(key, var.set_int32(value)));
    _order.push_back(key);
    return *this;
}

cose_data& cose_data::add(int key, const char* value) {
    if (value) {
        variant var;
        _data_map.insert(std::make_pair(key, var.set_bstr_new((unsigned char*)value, strlen(value))));
        _order.push_back(key);
    }
    return *this;
}

cose_data& cose_data::add(int key, const unsigned char* value, size_t size) {
    variant var;
    _data_map.insert(std::make_pair(key, var.set_bstr_new(value, size)));
    _order.push_back(key);
    return *this;
}

cose_data& cose_data::replace(int key, const unsigned char* value, size_t size) {
    cose_variantmap_t::iterator iter = _data_map.find(key);
    if (_data_map.end() != iter) {
        variant var;
        var.set_bstr_new(value, size);
        iter->second.move(var);
    } else {
        variant var;
        _data_map.insert(std::make_pair(key, var.set_bstr_new(value, size)));
        _order.push_back(key);
    }
    return *this;
}

cose_data& cose_data::add(int key, std::string& value) { return add(key, (unsigned char*)value.c_str(), value.size()); }

cose_data& cose_data::add(int key, std::string const& value) { return add(key, (unsigned char*)value.c_str(), value.size()); }

cose_data& cose_data::add(int key, binary_t& value) { return add(key, &value[0], value.size()); }

cose_data& cose_data::add(int key, binary_t const& value) { return add(key, &value[0], value.size()); }

cose_data& cose_data::replace(int key, binary_t const& value) { return replace(key, &value[0], value.size()); }

cose_data& cose_data::add(int key, uint16 curve, binary_t const& x, binary_t const& y) {
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

cose_data& cose_data::add(int key, uint16 curve, binary_t const& x, binary_t const& y, std::list<int>& order) {
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

cose_data& cose_data::add(int key, uint16 curve, binary_t const& x, bool ysign) {
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

cose_data& cose_data::add(int key, uint16 curve, binary_t const& x, bool ysign, std::list<int>& order) {
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

cose_data& cose_data::add(cose_alg_t alg, const char* kid, binary_t const& signature) {
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
        _data_map.insert(std::make_pair(key, vt.set_user_type(vty, p)));
        _order.push_back(key);
    }
    return *this;
}

cose_data& cose_data::add(int key, variant& value) {
    _data_map.insert(std::make_pair(key, value));
    _order.push_back(key);
    return *this;
}

cose_data& cose_data::set(binary_t const& bin) {
    _payload = bin;
    return *this;
}

cose_data& cose_data::set(std::string const& value) {
    _payload = convert(value);
    return *this;
}

cose_data& cose_data::set_b16(std::string const value) {
    _payload = base16_decode(value);
    return *this;
}

cose_data& cose_data::set_b16(const char* value) {
    if (value) {
        _payload = base16_decode(value, strlen(value));
    }
    return *this;
}

cose_data& cose_data::clear() {
    _data_map.clear();
    _order.clear();
    _payload.clear();
    for (std::list<cose_key*>::iterator it = _keys.begin(); it != _keys.end(); it++) {
        cose_key* object = *it;
        delete object;
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

                cose_orderlist_t::iterator list_iter;
                for (list_iter = _order.begin(); list_iter != _order.end(); list_iter++) {
                    int key = *list_iter;

                    cose_variantmap_t::iterator map_iter = _data_map.find(key);
                    variant value = map_iter->second;
                    *part_protected << new cbor_pair(new cbor_data(key), new cbor_data(value));
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

                cose_orderlist_t::iterator list_iter;
                for (list_iter = _order.begin(); list_iter != _order.end(); list_iter++) {
                    int key = *list_iter;

                    cose_variantmap_t::iterator unsent_iter = unsent.find(key);
                    if (unsent.end() != unsent_iter) {
                        continue;
                    }

                    cose_variantmap_t::iterator map_iter = _data_map.find(key);
                    variant value = map_iter->second;
                    *part_protected << new cbor_pair(new cbor_data(key), new cbor_data(value));
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

        cose_orderlist_t::iterator list_iter;
        for (list_iter = _order.begin(); list_iter != _order.end(); list_iter++) {
            int key = *list_iter;

            cose_variantmap_t::iterator map_iter = _data_map.find(key);
            variant value = map_iter->second;
            variant_t& vt = value.content();

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

        cose_orderlist_t::iterator list_iter;
        for (list_iter = _order.begin(); list_iter != _order.end(); list_iter++) {
            int key = *list_iter;

            cose_variantmap_t::iterator unsent_iter = unsent.find(key);
            if (unsent.end() != unsent_iter) {
                continue;
            }

            cose_variantmap_t::iterator map_iter = _data_map.find(key);
            variant value = map_iter->second;
            variant_t& vt = value.content();

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

cose_protected::cose_protected() {}

cose_protected::~cose_protected() {}

cose_protected& cose_protected::add(cose_key_t key, uint32 value) {
    _protected.add(key, value);
    return *this;
}

cose_protected& cose_protected::set(binary_t const& bin) {
    _protected.set(bin);
    cbor_object* root = nullptr;
    cbor_parse(&root, bin);
    if (root) {
        cbor_data* object = cbor_typeof<cbor_data>(root, cbor_type_t::cbor_type_data);
        if (object) {
            set(object);
        }
        root->release();
    }
    return *this;
}

return_t cose_protected::set(cbor_data* object) { return _protected.parse_protected(object); }

cose_data& cose_protected::data() { return _protected; }

cose_protected& cose_protected::clear() {
    _protected.clear();
    return *this;
}

cbor_data* cose_protected::cbor() {
    cbor_data* object = nullptr;
    _protected.build_protected(&object);
    return object;
}

cose_unprotected::cose_unprotected() {}

cose_unprotected::~cose_unprotected() {}

cose_unprotected& cose_unprotected::add(cose_key_t key, int32 value) {
    _unprotected.add(key, value);
    return *this;
}

cose_unprotected& cose_unprotected::add(cose_key_t key, const char* value) {
    _unprotected.add(key, value);
    return *this;
}

cose_unprotected& cose_unprotected::add(cose_key_t key, std::string& value) {
    _unprotected.add(key, value);
    return *this;
}

cose_unprotected& cose_unprotected::add(cose_key_t key, std::string const& value) {
    _unprotected.add(key, value);
    return *this;
}

cose_unprotected& cose_unprotected::add(cose_key_t key, binary_t& value) {
    _unprotected.add(key, value);
    return *this;
}

cose_unprotected& cose_unprotected::add(cose_key_t key, binary_t const& value) {
    _unprotected.add(key, value);
    return *this;
}

cose_unprotected& cose_unprotected::add(cose_key_t key, uint16 curve, binary_t const& x, binary_t const& y) {
    _unprotected.add(key, curve, x, y);
    return *this;
}

cose_unprotected& cose_unprotected::add(cose_key_t key, uint16 curve, binary_t const& x, bool ysign) {
    _unprotected.add(key, curve, x, ysign);
    return *this;
}

cose_unprotected& cose_unprotected::add(cose_alg_t alg, const char* kid, binary_t const& signature) {
    _unprotected.add(alg, kid, signature);
    return *this;
}

return_t cose_unprotected::set(cbor_map* object) { return _unprotected.parse_unprotected(object); }

cose_data& cose_unprotected::data() { return _unprotected; }

cose_unprotected& cose_unprotected::clear() {
    _unprotected.clear();
    return *this;
}

cbor_map* cose_unprotected::cbor() {
    cbor_map* object = nullptr;
    _unprotected.build_unprotected(&object);
    return object;
}

cose_binary::cose_binary() {}

cose_binary& cose_binary::set_b16(const char* value) {
    _payload.set_b16(value);
    return *this;
}

cose_binary& cose_binary::set_b16(std::string const& value) {
    _payload.set_b16(value);
    return *this;
}

cose_binary& cose_binary::set(std::string const& value) {
    _payload.set(value);
    return *this;
}

cose_binary& cose_binary::set(binary_t const& value) {
    _payload.set(value);
    return *this;
}

return_t cose_binary::set(cbor_data* object) { return _payload.parse_payload(object); }

cose_data& cose_binary::data() { return _payload; }

bool cose_binary::empty() { return _payload.empty_binary(); }

size_t cose_binary::size() { return _payload.size_binary(); }

void cose_binary::get(binary_t& bin) { _payload.get_binary(bin); }

cose_binary& cose_binary::clear() {
    _payload.clear();
    return *this;
}

cbor_data* cose_binary::cbor() {
    cbor_data* object = nullptr;
    _payload.build_data(&object);
    return object;
}

cose_recipient::cose_recipient()
    : _upperlayer(nullptr),
      _depth(0),
      _property(cose_property_t::cose_property_normal),
      _composer(nullptr),
      _cbor_tag(cbor_tag_t::cbor_tag_unknown),
      _countersigns(nullptr) {
    get_protected().data().set_owner(this);
    get_unprotected().data().set_owner(this);
    get_payload().data().set_owner(this);
    get_singleitem().data().set_owner(this);
    get_recipients().set_upperlayer(this);
}

cose_recipient::~cose_recipient() {
    if (_countersigns) {
        delete _countersigns;
    }
}

void cose_recipient::set_upperlayer(cose_recipient* layer) {
    _upperlayer = layer;
    set_composer(layer->get_composer());

    if (layer) {
        _depth = layer->get_depth() + 1;
    }
}

cose_recipient* cose_recipient::get_upperlayer() { return _upperlayer; }

cose_recipient* cose_recipient::get_upperlayer2() {
    cose_recipient* layer = nullptr;
    if (_upperlayer) {
        layer = _upperlayer;
    } else {
        layer = this;  // aka body, composer.get_layer()
    }
    return layer;
}

uint16 cose_recipient::get_depth() { return _depth; }

void cose_recipient::set_composer(cose_composer* composer) { _composer = composer; }

cose_composer* cose_recipient::get_composer() { return _composer; }

cose_recipient& cose_recipient::set_property(uint16 property) {
    _property = property;
    return *this;
}

uint16 cose_recipient::get_property() { return _property; }

cose_recipient& cose_recipient::add(cose_recipient* recipient) {
    cose_recipient* object = recipient;
    if (nullptr == object) {
        object = new cose_recipient;
    }

    object->set_upperlayer(this);
    object->set_composer(get_composer());

    return _recipients.add(object);
}

return_t cose_recipient::finditem(int key, int& value, int scope) {
    return_t ret = errorcode_t::not_found;
    __try2 {
        if (cose_scope::cose_scope_unsent & scope) {
            ret = get_composer()->get_unsent().data().finditem(key, value);
            if (errorcode_t::success == ret) {
                __leave2;
            }
        }
        if (cose_scope::cose_scope_protected & scope) {
            ret = get_protected().data().finditem(key, value);
            if (errorcode_t::success == ret) {
                __leave2;
            }
        }
        if (cose_scope::cose_scope_unprotected & scope) {
            ret = get_unprotected().data().finditem(key, value);
            if (errorcode_t::success == ret) {
                __leave2;
            }
        }
        if (cose_scope::cose_scope_children & scope) {
            ret = get_recipients().finditem(key, value, scope);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cose_recipient::finditem(int key, std::string& value, int scope) {
    return_t ret = errorcode_t::not_found;
    __try2 {
        if (cose_scope::cose_scope_unsent & scope) {
            ret = get_composer()->get_unsent().data().finditem(key, value);
            if (errorcode_t::success == ret) {
                __leave2;
            }
        }
        if (cose_scope::cose_scope_protected & scope) {
            ret = get_protected().data().finditem(key, value);
            if (errorcode_t::success == ret) {
                __leave2;
            }
        }
        if (cose_scope::cose_scope_unprotected & scope) {
            ret = get_unprotected().data().finditem(key, value);
            if (errorcode_t::success == ret) {
                __leave2;
            }
        }
        if (cose_scope::cose_scope_children & scope) {
            ret = get_recipients().finditem(key, value, scope);
            if (errorcode_t::success == ret) {
                __leave2;
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cose_recipient::finditem(int key, binary_t& value, int scope) {
    return_t ret = errorcode_t::not_found;
    __try2 {
        if (cose_scope::cose_scope_unsent & scope) {
            ret = get_composer()->get_unsent().data().finditem(key, value);
            if (errorcode_t::success == ret) {
                __leave2;
            }
        }
        if (cose_scope::cose_scope_params & scope) {
            ret = get_params().finditem(key, value);
            if (errorcode_t::success == ret) {
                __leave2;
            }
        }
        if (cose_scope::cose_scope_protected & scope) {
            ret = get_protected().data().finditem(key, value);
            if (errorcode_t::success == ret) {
                __leave2;
            }
        }
        if (cose_scope::cose_scope_unprotected & scope) {
            ret = get_unprotected().data().finditem(key, value);
            if (errorcode_t::success == ret) {
                __leave2;
            }
        }
        if (cose_scope::cose_scope_children & scope) {
            ret = get_recipients().finditem(key, value, scope);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cose_recipient::setparam(cose_param_t id, binary_t const& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        switch (id) {
            case cose_param_t::cose_param_cek:
            case cose_param_t::cose_param_ciphertext:
            case cose_param_t::cose_param_secret:
            case cose_param_t::cose_param_plaintext:
                get_params().replace(id, bin);
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

return_t cose_recipient::getparam(cose_param_t id, binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        switch (id) {
            case cose_param_t::cose_param_cek:
            case cose_param_t::cose_param_ciphertext:
            case cose_param_t::cose_param_secret:
            case cose_param_t::cose_param_plaintext:
                get_params().replace(id, bin);
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

return_t cose_recipient::parse(cbor_array* root) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    cbor_tag_t cbor_tag = cbor_tag_t::cbor_tag_unknown;

    __try2 {
        clear();

        if (nullptr == root) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = parse_header(root);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = parse_message(root);
        if (errorcode_t::success != ret) {
            __leave2;
        }
    }
    __finally2 {
        // do nothing
        if (errorcode_t::success != ret) {
            // throw;
        }
    }
    return ret;
}

return_t cose_recipient::parse_header(cbor_array* root) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == root) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        size_t size_message = root->size();

        if (size_message < 3) {
            ret = errorcode_t::bad_format;
            __leave2;
        }

        // parse protected and unprotected
        ret = parse_protected((*root)[0]);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = parse_unprotected((*root)[1]);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = parse_payload((*root)[2]);
        if (errorcode_t::success != ret) {
            __leave2;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cose_recipient::parse_message(cbor_array* root) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    size_t i = 0;

    __try2 {
        if (nullptr == root) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        size_t size_message = root->size();
        for (i = 3; i < size_message; i++) {
            cbor_object* cbor_item = (*root)[i];

            // in case of cose_tag_mac/cose_tag_mac0
            cbor_data* cbor_singleitem = cbor_typeof<cbor_data>(cbor_item, cbor_type_t::cbor_type_data);
            if (cbor_singleitem) {
                parse_singleitem(cbor_item);
                continue;
            }

            // in case of cose_tag_encrypt/cose_tag_mac/cose_tag_sign
            cbor_array* cbor_recipients = cbor_typeof<cbor_array>(cbor_item, cbor_type_t::cbor_type_array);
            if (cbor_recipients) {
                for (size_t size = 0; size < cbor_recipients->size(); size++) {
                    cbor_array* cbor_recipient = cbor_typeof<cbor_array>((*cbor_recipients)[size], cbor_type_t::cbor_type_array);
                    if (cbor_recipient) {
                        add().parse(cbor_recipient);
                    }
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

return_t cose_recipient::parse_protected(cbor_object* object) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cbor_data* cbor_protected = cbor_typeof<cbor_data>(object, cbor_type_t::cbor_type_data);
        if (nullptr == cbor_protected) {
            ret = errorcode_t::bad_format;
            __leave2;
        }

        ret = get_protected().set(cbor_protected);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cose_recipient::parse_unprotected(cbor_object* object) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cbor_map* cbor_unprotected = cbor_typeof<cbor_map>(object, cbor_type_t::cbor_type_map);
        if (nullptr == cbor_unprotected) {
            ret = errorcode_t::bad_format;
            __leave2;
        }

        ret = get_unprotected().set(cbor_unprotected);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cose_recipient::parse_payload(cbor_object* object) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cbor_data* cbor_payload = cbor_typeof<cbor_data>(object, cbor_type_t::cbor_type_data);
        if (nullptr == cbor_payload) {
            ret = errorcode_t::bad_format;
            __leave2;
        }

        ret = get_payload().set(cbor_payload);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cose_recipient::parse_singleitem(cbor_object* object) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cbor_data* cbor_singleitem = cbor_typeof<cbor_data>(object, cbor_type_t::cbor_type_data);
        if (nullptr == cbor_singleitem) {
            ret = errorcode_t::bad_format;
            __leave2;
        }

        ret = get_singleitem().set(cbor_singleitem);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

cose_protected& cose_recipient::get_protected() { return _protected; }

cose_unprotected& cose_recipient::get_unprotected() { return _unprotected; }

cose_binary& cose_recipient::get_payload() { return _payload; }

cose_binary& cose_recipient::get_singleitem() { return _singleitem; }

cose_binary& cose_recipient::get_signature() { return _singleitem; }

cose_binary& cose_recipient::get_tag() { return _singleitem; }

cose_recipients& cose_recipient::get_recipients() { return _recipients; }

cose_data& cose_recipient::get_params() { return _params; }

crypto_key& cose_recipient::get_static_key() { return _static_key; }

cose_countersigns* cose_recipient::get_countersigns0() { return _countersigns; }

cose_countersigns* cose_recipient::get_countersigns1() {
    if (nullptr == _countersigns) {
        _countersigns = new cose_countersigns;
        _countersigns->set_upperlayer(this);
    }
    return _countersigns;
}

cose_recipient& cose_recipient::clear() {
    _cbor_tag = cbor_tag_t::cbor_tag_unknown;
    get_protected().clear();
    get_unprotected().clear();
    get_payload().clear();
    get_singleitem().clear();
    get_recipients().clear();
    if (_countersigns) {
        delete _countersigns;
        _countersigns = nullptr;
    }
    get_static_key().clear();
    get_params().clear();
    return *this;
}

cose_alg_t cose_recipient::get_algorithm() {
    int alg = cose_alg_t::cose_unknown;
    get_protected().data().finditem(cose_key_t::cose_alg, alg);
    if (cose_alg_t::cose_unknown == alg) {
        get_unprotected().data().finditem(cose_key_t::cose_alg, alg);
    }
    return (cose_alg_t)alg;
}

std::string cose_recipient::get_kid() {
    std::string kid;
    get_unprotected().data().finditem(cose_key_t::cose_kid, kid);
    return kid;
}

void cose_recipient::for_each(void (*for_each_handler)(cose_layer*, void* userdata), void* userdata) {
    if (for_each_handler) {
        for_each_handler(this, userdata);
        _recipients.for_each(for_each_handler, userdata);
    }
}

cbor_array* cose_recipient::cbor() {
    cbor_array* object = new cbor_array;
    *object << get_protected().cbor() << get_unprotected().cbor() << get_payload().cbor();
    if (_recipients.size()) {
        *object << _recipients.cbor();
    }
    return object;
}

cose_recipients::cose_recipients() : _upperlayer(nullptr) {}

cose_recipients::~cose_recipients() { clear(); }

cose_recipient& cose_recipients::add(cose_recipient* recipient) {
    recipient->set_upperlayer(get_upperlayer());
    std::list<cose_recipient*>::iterator iter = _recipients.insert(_recipients.end(), recipient);
    return **iter;
}

cose_recipients& cose_recipients::clear() {
    for (std::list<cose_recipient*>::iterator iter = _recipients.begin(); iter != _recipients.end(); iter++) {
        cose_recipient* item = *iter;
        delete item;
    }
    _recipients.clear();
    return *this;
}

bool cose_recipients::empty() { return (0 == _recipients.size()); }

size_t cose_recipients::size() { return _recipients.size(); }

cose_recipient* cose_recipients::operator[](size_t index) {
    cose_recipient* object = nullptr;
    if (index < _recipients.size()) {
        std::list<cose_recipient*>::iterator iter = _recipients.begin();
        std::advance(iter, index);
        object = *iter;
    }
    return object;
}

void cose_recipients::for_each(void (*for_each_handler)(cose_layer*, void* userdata), void* userdata) {
    if (for_each_handler) {
        std::list<cose_recipient*>::iterator iter;
        for (iter = _recipients.begin(); iter != _recipients.end(); iter++) {
            cose_recipient* item = *iter;
            item->for_each(for_each_handler, userdata);
        }
    }
}

cose_recipients& cose_recipients::set_upperlayer(cose_recipient* layer) {
    _upperlayer = layer;
    return *this;
}

cose_recipient* cose_recipients::get_upperlayer() { return _upperlayer; }

return_t cose_recipients::finditem(int key, int& value, int scope) {
    return_t ret = errorcode_t::not_found;
    std::list<cose_recipient*>::iterator iter;
    for (iter = _recipients.begin(); iter != _recipients.end(); iter++) {
        cose_recipient* item = *iter;
        ret = item->finditem(key, value, scope);
        if (errorcode_t::success == ret) {
            break;
        }
    }
    return ret;
}

return_t cose_recipients::finditem(int key, std::string& value, int scope) {
    return_t ret = errorcode_t::not_found;
    std::list<cose_recipient*>::iterator iter;
    for (iter = _recipients.begin(); iter != _recipients.end(); iter++) {
        cose_recipient* item = *iter;
        ret = item->finditem(key, value, scope);
        if (errorcode_t::success == ret) {
            break;
        }
    }
    return ret;
}

return_t cose_recipients::finditem(int key, binary_t& value, int scope) {
    return_t ret = errorcode_t::not_found;
    std::list<cose_recipient*>::iterator iter;
    for (iter = _recipients.begin(); iter != _recipients.end(); iter++) {
        cose_recipient* item = *iter;
        ret = item->finditem(key, value, scope);
        if (errorcode_t::success == ret) {
            break;
        }
    }
    return ret;
}

cbor_array* cose_recipients::cbor() {
    cbor_array* object = new cbor_array;
    std::list<cose_recipient*>::iterator iter;
    for (iter = _recipients.begin(); iter != _recipients.end(); iter++) {
        cose_recipient* item = *iter;
        *object << item->cbor();
    }
    return object;
}

cose_unsent::cose_unsent() {}

cose_unsent::~cose_unsent() {}

cose_data& cose_unsent::data() { return _unsent; }

bool cose_unsent::isvalid(int key) {
    bool ret = true;
    switch (key) {
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
            break;
        default:
            ret = false;
            break;
    }
    return ret;
}

cose_unsent& cose_unsent::add(int key, const char* value) {
    if (value && isvalid(key)) {
        _unsent.add(key, value);
    }
    return *this;
}

cose_unsent& cose_unsent::add(int key, const unsigned char* value, size_t size) {
    if (value && isvalid(key)) {
        _unsent.add(key, value, size);
    }
    return *this;
}

cose_unsent& cose_unsent::add(int key, binary_t& value) {
    if (isvalid(key)) {
        _unsent.add(key, value);
    }
    return *this;
}

cose_unsent& cose_unsent::add(int key, binary_t const& value) {
    if (isvalid(key)) {
        _unsent.add(key, value);
    }
    return *this;
}

cose_composer::cose_composer() : _cbor_tag(cbor_tag_t::cbor_tag_unknown) { get_layer().set_composer(this); }

return_t cose_composer::compose(cbor_array** object, bool tagged) {
    return_t ret = errorcode_t::success;

    // implementation sketch

    // read algorithm from protected or unprotected
    // sizeof_recipients = get_recipients().size()
    // switch(cose_group_t)
    //   case cose_group_sign_ecdsa:
    //   case cose_group_sign_eddsa:
    //   case cose_group_sign_rsassa_pss:
    //   case cose_group_sign_rsassa_pkcs15:
    //      if(sizeof_recipients) tag = cose_tag_sign;
    //      else tag = cose_tag_sign1;
    //   case cose_group_enc_aesgcm:
    //   case cose_group_enc_aesccm:
    //   case cose_group_enc_chacha20_poly1305:
    //      if(sizeof_recipients) tag = cose_tag_encrypt
    //      else tag = cose_tag_encrypt0;
    //   case cose_group_mac_hmac:
    //   case cose_group_mac_aes:
    //      if(sizeof_recipients) tag = cose_tag_mac
    //      else tag = cose_tag_mac0;

    //   then call compose(tag, object);

    cbor_array* root = nullptr;
    cbor_tag_t cbor_tag = cbor_tag_t::cbor_tag_unknown;

    __try2 {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        __try_new_catch(root, new cbor_array, ret, __leave2);

        if (cbor_tag_t::cbor_tag_unknown != _cbor_tag) {
            cbor_tag = _cbor_tag;
        } else {
            crypto_advisor* advisor = crypto_advisor::get_instance();
            int alg = 0;
            get_layer().finditem(cose_key_t::cose_alg, alg, cose_scope_protected | cose_scope_unprotected | cose_scope_children);
            crypt_category_t category = advisor->categoryof((cose_alg_t)alg);
            size_t size_recipients = get_recipients().size();
            switch (category) {
                case crypt_category_t::crypt_category_crypt:
                    cbor_tag = size_recipients ? cose_tag_encrypt : cose_tag_encrypt0;
                    break;
                case crypt_category_t::crypt_category_mac:
                    cbor_tag = size_recipients ? cose_tag_mac : cose_tag_mac0;
                    break;
                case crypt_category_t::crypt_category_sign:
                    cbor_tag = size_recipients ? cose_tag_sign : cose_tag_sign1;
                    break;
                default:
                    break;
            }
        }

        *root << get_protected().cbor() << get_unprotected().cbor() << get_payload().cbor();
        if (tagged) {
            root->tag(cbor_tag);
        }

        if ((cbor_tag_t::cose_tag_mac == cbor_tag) || (cbor_tag_t::cose_tag_mac0 == cbor_tag) || (cbor_tag_t::cose_tag_sign1 == cbor_tag)) {
            *root << get_singleitem().cbor();
        }
        if ((cbor_tag_t::cose_tag_encrypt == cbor_tag) || (cbor_tag_t::cose_tag_sign == cbor_tag) || (cbor_tag_t::cose_tag_mac == cbor_tag)) {
            if (get_recipients().size()) {
                *root << get_recipients().cbor();
            }
        }

        *object = root;
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t cose_composer::compose(cbor_array** object, binary_t& cbor, bool tagged) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        ret = compose(object, tagged);
        if (errorcode_t::success == ret) {
            cbor_publisher publisher;
            publisher.publish(*object, &cbor);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cose_composer::diagnose(cbor_array** object, basic_stream& stream, bool tagged) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        ret = compose(object, tagged);
        if (errorcode_t::success == ret) {
            cbor_publisher publisher;
            publisher.publish(*object, &stream);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cose_composer::parse(binary_t const& input) {
    return_t ret = errorcode_t::success;
    cbor_object* root = nullptr;
    cbor_array* cbor_message = nullptr;

    __try2 {
        clear();

        if (0 == input.size()) {
            __leave2;
        }

        // parse cbor
        ret = cbor_parse(&root, input);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // check
        cbor_array* cbor_message = cbor_typeof<cbor_array>(root, cbor_type_t::cbor_type_array);
        if (nullptr == cbor_message) {
            ret = errorcode_t::bad_format;
            __leave2;
        }
        if (cbor_message->tagged()) {
            _cbor_tag = cbor_message->tag_value();
        }

        // parse cose
        ret = get_layer().parse(cbor_message);
    }
    __finally2 {
        if (root) {
            root->release();
        }
    }
    return ret;
}

void cose_composer::clear() {
    get_protected().clear();
    get_unprotected().clear();
    get_payload().clear();
    get_singleitem().clear();
    get_recipients().clear();
}

cose_protected& cose_composer::get_protected() { return get_layer().get_protected(); }

cose_unprotected& cose_composer::get_unprotected() { return get_layer().get_unprotected(); }

cose_binary& cose_composer::get_payload() { return get_layer().get_payload(); }

cose_binary& cose_composer::get_tag() { return get_layer().get_singleitem(); }

cose_binary& cose_composer::get_signature() { return get_layer().get_singleitem(); }

cose_binary& cose_composer::get_singleitem() { return get_layer().get_singleitem(); }

cose_recipients& cose_composer::get_recipients() { return get_layer().get_recipients(); }

cose_layer& cose_composer::get_layer() { return _layer; }

cose_unsent& cose_composer::get_unsent() { return _unsent; }

cbor_tag_t cose_composer::get_cbor_tag() { return _cbor_tag; }

}  // namespace crypto
}  // namespace hotplace
