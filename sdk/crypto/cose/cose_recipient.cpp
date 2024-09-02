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
using namespace io;
namespace crypto {

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

return_t cose_recipient::setparam(cose_param_t id, const binary_t& bin) {
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
                ret = errorcode_t::bad_request;
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
                ret = errorcode_t::bad_request;
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

}  // namespace crypto
}  // namespace hotplace
