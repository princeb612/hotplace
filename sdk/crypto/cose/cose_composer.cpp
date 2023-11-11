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

class cose_key {
   public:
    cose_key() : _curve(0) {}
    void set(uint16 curve, binary_t const& x, binary_t const& y) {
        _curve = curve;
        _x = x;
        _y = y;
        _compressed = false;
    }
    void set(uint16 curve, binary_t const& x, bool ysign) {
        _curve = curve;
        _x = x;
        _y.clear();
        _ysign = ysign;
        _compressed = true;
    }
    cbor_map* cbor() {
        cbor_map* object = nullptr;
        __try2 {
            __try_new_catch_only(object, new cbor_map());
            if (nullptr == object) {
                __leave2;
            }

            *object << new cbor_pair(cose_key_lable_t::cose_lable_kty, new cbor_data(cose_kty_t::cose_kty_ec2))  // kty(1)
                    << new cbor_pair(cose_key_lable_t::cose_ec_crv, new cbor_data(_curve))                       // crv(-1)
                    << new cbor_pair(cose_key_lable_t::cose_ec_x, new cbor_data(_x));                            // x(-2)

            if (_compressed) {
                *object << new cbor_pair(cose_key_lable_t::cose_ec_y, new cbor_data(_ysign));  // y(-3)
            } else {
                *object << new cbor_pair(cose_key_lable_t::cose_ec_y, new cbor_data(_y));  // y(-3)
            }
        }
        __finally2 {
            // do nothing
        }
        return object;
    }

   private:
    uint16 _curve;
    binary_t _x;
    binary_t _y;
    bool _ysign;
    bool _compressed;
};

class cose_countersign {
   public:
    cose_countersign() {}

    cose_protected& get_protected() { return _protected; }
    cose_unprotected& get_unprotected() { return _unprotected; }
    cose_binary& get_signature() { return _signature; }
    cbor_array* cbor() {
        cbor_array* object = new cbor_array;
        *object << get_protected().cbor() << get_unprotected().cbor() << get_signature().cbor();
        return object;
    }

   private:
    cose_protected _protected;
    cose_unprotected _unprotected;
    cose_binary _signature;
};

class cose_countersigns {
   public:
    cose_countersigns() {}

    cose_countersign& add(cose_countersign* countersign) {
        std::list<cose_countersign*>::iterator iter = _countersigns.insert(_countersigns.end(), countersign);
        return **iter;
    }
    bool empty() { return 0 == _countersigns.size(); }
    cbor_array* cbor() {
        cbor_array* object = nullptr;
        __try2 {
            __try_new_catch_only(object, new cbor_array);
            if (object) {
                std::list<cose_countersign*>::iterator iter;
                for (iter = _countersigns.begin(); iter != _countersigns.end(); iter++) {
                    cose_countersign* sign = *iter;
                    *object << sign->cbor();
                }
            }
        }
        __finally2 {
            // do nothing
        }
        return object;
    }

   private:
    std::list<cose_countersign*> _countersigns;
};

cbor_object_signing_encryption_composer::cbor_object_signing_encryption_composer() {}

cbor_object_signing_encryption_composer::composer::composer() {
    // do nothing
}

return_t cbor_object_signing_encryption_composer::compose(cbor_tag_t cbor_tag, cbor_array** node) {
    return_t ret = errorcode_t::success;
    composer composer;

    cbor_array* root = new cbor_array;
    root->tag(cbor_tag);
    *root << get_protected().cbor() << get_unprotected().cbor() << get_payload().cbor();
    if ((cbor_tag_t::cose_tag_mac == cbor_tag) || (cbor_tag_t::cose_tag_mac0 == cbor_tag)) {
        *root << get_tag().cbor();
    }
    if (get_recipients().empty()) {
        if ((cbor_tag_t::cose_tag_encrypt0 == cbor_tag) || (cbor_tag_t::cose_tag_mac0 == cbor_tag)) {
            // do nothing
        } else {
            *root << get_singleitem().cbor();
        }
    } else {
        *root << get_recipients().cbor();
    }

    *node = root;

    return ret;
}

cose_protected& cbor_object_signing_encryption_composer::get_protected() { return _protected; }

cose_unprotected& cbor_object_signing_encryption_composer::get_unprotected() { return _unprotected; }

cose_binary& cbor_object_signing_encryption_composer::get_payload() { return _payload; }

cose_binary& cbor_object_signing_encryption_composer::get_tag() { return _tag; }

cose_binary& cbor_object_signing_encryption_composer::get_singleitem() { return _singleitem; }

cose_recipients& cbor_object_signing_encryption_composer::get_recipients() { return _recipients; }

return_t cbor_object_signing_encryption_composer::composer::build_protected(cbor_data** object) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cbor_data* part_protected = nullptr;
        binary_t dummy;
        __try_new_catch(part_protected, new cbor_data(dummy), ret, __leave2);
        *object = part_protected;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption_composer::composer::build_protected(cbor_data** object, cose_variantmap_t& input) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (0 == input.size()) {
            cbor_data* part_protected = nullptr;
            binary_t dummy;
            __try_new_catch(part_protected, new cbor_data(dummy), ret, __leave2);
            *object = part_protected;
        } else {
            binary_t bin_protected;
            cbor_map* part_protected = nullptr;

            __try_new_catch(part_protected, new cbor_map(), ret, __leave2);

            cose_variantmap_t::iterator map_iter;
            for (map_iter = input.begin(); map_iter != input.end(); map_iter++) {
                int key = map_iter->first;
                variant_t& value = map_iter->second;
                *part_protected << new cbor_pair(new cbor_data(key), new cbor_data(value));
            }

            build_protected(object, part_protected);

            part_protected->release();
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption_composer::composer::build_protected(cbor_data** object, cose_variantmap_t& input, cose_orderlist_t& order) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (0 == input.size()) {
            cbor_data* part_protected = nullptr;
            binary_t dummy;
            __try_new_catch(part_protected, new cbor_data(dummy), ret, __leave2);
            *object = part_protected;
        } else {
            binary_t bin_protected;
            cbor_map* part_protected = nullptr;

            __try_new_catch(part_protected, new cbor_map(), ret, __leave2);

            cose_orderlist_t::iterator list_iter;
            for (list_iter = order.begin(); list_iter != order.end(); list_iter++) {
                int key = *list_iter;

                cose_variantmap_t::iterator map_iter = input.find(key);
                variant_t& value = map_iter->second;
                *part_protected << new cbor_pair(new cbor_data(key), new cbor_data(value));
            }

            build_protected(object, part_protected);

            part_protected->release();
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption_composer::composer::build_protected(cbor_data** object, cbor_map* input) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == object || nullptr == input) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        binary_t bin_protected;
        cbor_publisher publisher;
        publisher.publish(input, &bin_protected);

        *object = new cbor_data(bin_protected);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption_composer::composer::build_unprotected(cbor_map** object) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cbor_map* part_unprotected = nullptr;

        __try_new_catch(part_unprotected, new cbor_map(), ret, __leave2);

        *object = part_unprotected;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption_composer::composer::build_unprotected(cbor_map** object, cose_variantmap_t& input) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cbor_map* part_unprotected = nullptr;

        __try_new_catch(part_unprotected, new cbor_map(), ret, __leave2);

        cose_variantmap_t::iterator iter;
        for (iter = input.begin(); iter != input.end(); iter++) {
            int key = iter->first;
            variant_t& value = iter->second;

            if (TYPE_STATIC_KEY == value.type) {
                cose_key* k = (cose_key*)value.data.p;
                *part_unprotected << new cbor_pair(key, k->cbor());
            } else if (TYPE_COUNTER_SIG == value.type) {
                cose_countersign* sign = (cose_countersign*)value.data.p;
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

return_t cbor_object_signing_encryption_composer::composer::build_unprotected(cbor_map** object, cose_variantmap_t& input, cose_orderlist_t& order) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cbor_map* part_unprotected = nullptr;

        __try_new_catch(part_unprotected, new cbor_map(), ret, __leave2);

        cose_orderlist_t::iterator list_iter;
        for (list_iter = order.begin(); list_iter != order.end(); list_iter++) {
            int key = *list_iter;

            cose_variantmap_t::iterator map_iter = input.find(key);
            variant_t& value = map_iter->second;

            if (TYPE_STATIC_KEY == value.type) {
                cose_key* k = (cose_key*)value.data.p;
                *part_unprotected << new cbor_pair(key, k->cbor());
            } else if (TYPE_COUNTER_SIG == value.type) {
                cose_countersign* sign = (cose_countersign*)value.data.p;
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

return_t cbor_object_signing_encryption_composer::composer::build_data(cbor_data** object, const char* payload) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == object || nullptr == payload) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        __try_new_catch(*object, new cbor_data(convert(payload)), ret, __leave2);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption_composer::composer::build_data(cbor_data** object, const byte_t* payload, size_t size) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        __try_new_catch(*object, new cbor_data(payload, size), ret, __leave2);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption_composer::composer::build_data(cbor_data** object, binary_t const& payload) {
    return build_data(object, &payload[0], payload.size());
}

return_t cbor_object_signing_encryption_composer::composer::build_data_b16(cbor_data** object, const char* str) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == object || nullptr == str) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        __try_new_catch(*object, new cbor_data(base16_decode(str)), ret, __leave2);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

cose_protected::cose_protected() {}

cose_protected::~cose_protected() { cose_variantmap_free(_protected_map); }

cose_protected& cose_protected::add(cose_key_t key, uint16 value) {
    _protected_map.insert(std::make_pair(key, variant_int16(value)));
    return *this;
}

cose_protected& cose_protected::set(binary_t const& bin) {
    _bin = bin;
    return *this;
}

cbor_data* cose_protected::cbor() {
    cbor_data* object = nullptr;
    cbor_object_signing_encryption_composer::composer composer;
    if (_bin.size()) {
        object = new cbor_data(_bin);
    } else {
        composer.build_protected(&object, _protected_map);
    }
    return object;
}

cose_unprotected::cose_unprotected() {}

cose_unprotected::~cose_unprotected() {
    cose_variantmap_t::iterator map_iter;
    for (map_iter = _unprotected_map.begin(); map_iter != _unprotected_map.end(); map_iter++) {
        int key = map_iter->first;
        variant_t& value = map_iter->second;
        if (TYPE_STATIC_KEY == value.type) {
            cose_key* k = (cose_key*)value.data.p;
            delete k;
        } else if (TYPE_COUNTER_SIG == value.type) {
            cose_countersign* s = (cose_countersign*)value.data.p;
            delete s;
        } else {
            variant_free(value);
        }
    }
    _unprotected_map.clear();
}

cose_unprotected& cose_unprotected::add(cose_key_t key, uint16 value) {
    _unprotected_map.insert(std::make_pair(key, variant_int16(value)));
    _order.push_back(key);
    return *this;
}

cose_unprotected& cose_unprotected::add(cose_key_t key, const char* value) {
    if (value) {
        _unprotected_map.insert(std::make_pair(key, variant_bstr_new((unsigned char*)value, strlen(value))));
        _order.push_back(key);
    }
    return *this;
}

cose_unprotected& cose_unprotected::add(cose_key_t key, std::string const& value) {
    _unprotected_map.insert(std::make_pair(key, variant_bstr_new((unsigned char*)value.c_str(), value.size())));
    _order.push_back(key);
    return *this;
}

cose_unprotected& cose_unprotected::add(cose_key_t key, binary_t const& value) {
    _unprotected_map.insert(std::make_pair(key, variant_binary_new(value)));
    _order.push_back(key);
    return *this;
}

cose_unprotected& cose_unprotected::add(cose_key_t key, uint16 curve, binary_t const& x, binary_t const& y) {
    cose_key* k = nullptr;
    __try2 {
        __try_new_catch_only(k, new cose_key());
        if (k) {
            k->set(curve, x, y);
            variant_t vt;
            _unprotected_map.insert(std::make_pair(key, variant_set(vt, TYPE_STATIC_KEY, k)));
            _order.push_back(key);
        }
    }
    __finally2 {
        // do nothing
    }
    return *this;
}

cose_unprotected& cose_unprotected::add(cose_key_t key, uint16 curve, binary_t const& x, bool ysign) {
    cose_key* k = nullptr;
    __try2 {
        __try_new_catch_only(k, new cose_key());
        if (k) {
            k->set(curve, x, ysign);
            variant_t vt;
            _unprotected_map.insert(std::make_pair(key, variant_set(vt, TYPE_STATIC_KEY, k)));
            _order.push_back(key);
        }
    }
    __finally2 {
        // do nothing
    }
    return *this;
}

cose_unprotected& cose_unprotected::add(cose_alg_t alg, const char* kid, binary_t const& signature) {
    return_t ret = errorcode_t::success;
    __try2 {
        cose_variantmap_t::iterator iter = _unprotected_map.find(cose_key_t::cose_counter_sig);
        if (_unprotected_map.end() == iter) {
            cose_countersign* sign = nullptr;
            __try_new_catch_only(sign, new cose_countersign);
            if (sign) {
                sign->get_protected().add(cose_key_t::cose_alg, alg);
                if (kid) {
                    sign->get_unprotected().add(cose_key_t::cose_kid, kid);
                }
                sign->get_signature().set(signature);

                variant_t vt;
                variant_set(vt, TYPE_COUNTER_SIG, sign);
                _unprotected_map.insert(std::make_pair(cose_key_t::cose_counter_sig, vt));
                _order.push_back(cose_key_t::cose_counter_sig);
            }
        } else {
            ret = errorcode_t::already_exist;
        }
    }
    __finally2 {
        // do nothing
    }
    return *this;
}

cbor_map* cose_unprotected::cbor() {
    cbor_map* object = nullptr;
    cbor_object_signing_encryption_composer::composer composer;
    composer.build_unprotected(&object, _unprotected_map, _order);
    return object;
}

cose_orderlist_t& cose_unprotected::get_order() { return _order; }

cose_binary::cose_binary() {}

cose_binary& cose_binary::set_b16(const char* value) {
    if (value) {
        payload = base16_decode(value, strlen(value));
    }
    return *this;
}

cose_binary& cose_binary::set_b16(std::string const& value) {
    payload = base16_decode(value);
    return *this;
}

cose_binary& cose_binary::set(std::string const& value) {
    payload = convert(value);
    return *this;
}

cose_binary& cose_binary::set(binary_t const& value) {
    payload = value;
    return *this;
}

cbor_data* cose_binary::cbor() {
    cbor_data* object = nullptr;
    cbor_object_signing_encryption_composer::composer composer;
    composer.build_data(&object, payload);
    return object;
}

cose_recipient::cose_recipient() {}

cose_protected& cose_recipient::get_protected() { return _protected; }

cose_unprotected& cose_recipient::get_unprotected() { return _unprotected; }

cose_binary& cose_recipient::get_payload() { return _payload; }

cbor_array* cose_recipient::cbor() {
    cbor_array* object = new cbor_array;
    *object << get_protected().cbor() << get_unprotected().cbor() << get_payload().cbor();
    return object;
}

cose_recipients::cose_recipients() {}

cose_recipient& cose_recipients::add(cose_recipient* recipient) {
    std::list<cose_recipient*>::iterator iter = recipients.insert(recipients.end(), recipient);
    return **iter;
}

bool cose_recipients::empty() { return (0 == recipients.size()); }

cbor_array* cose_recipients::cbor() {
    cbor_array* object = new cbor_array;
    std::list<cose_recipient*>::iterator iter;
    for (iter = recipients.begin(); iter != recipients.end(); iter++) {
        cose_recipient* item = *iter;
        *object << item->cbor();
    }
    return object;
}

}  // namespace crypto
}  // namespace hotplace
