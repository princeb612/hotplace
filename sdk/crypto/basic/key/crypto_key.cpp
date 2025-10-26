/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/binary.hpp>
#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/crypto_key.hpp>
#include <hotplace/sdk/crypto/basic/evp_pkey.hpp>

namespace hotplace {
namespace crypto {

crypto_key::crypto_key() { _shared.make_share(this); }

crypto_key::crypto_key(const crypto_key& object) {
    _shared.make_share(this);

    _key_map = object._key_map;

    for (auto& pair : _key_map) {
        crypto_key_object& keyobj = pair.second;
        EVP_PKEY_up_ref((EVP_PKEY*)keyobj.get_pkey());
        auto x509 = keyobj.get_x509();
        if (x509) {
            X509_up_ref((X509*)x509);
        }
    }
}
crypto_key::crypto_key(crypto_key&& object) {
    _shared.make_share(this);

#if __cplusplus >= 201703L  // c++17
    _key_map.merge(object._key_map);
#else
    _key_map = object._key_map;
    object._key_map.clear();
#endif
}

crypto_key::~crypto_key() { clear(); }

return_t crypto_key::add(crypto_key_object key, bool up_ref) {
    return_t ret = errorcode_t::success;

    critical_section_guard guard(_lock);
    __try2 {
        if (nullptr == key.get_pkey()) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (crypto_use_t::use_unknown == (key.get_desc().get_use() & crypto_use_t::use_any)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        crypto_kty_t type = ktyof_evp_pkey(key);
        if (crypto_kty_t::kty_unknown == type) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        if (up_ref) {
            EVP_PKEY_up_ref((EVP_PKEY*)key.get_pkey());  // increments a reference counter
            auto x509 = key.get_x509();
            if (x509) {
                X509_up_ref((X509*)x509);
            }
        }

        _key_map.insert(std::make_pair(key.get_desc().get_kid_str(), key));
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            EVP_PKEY_free((EVP_PKEY*)key.get_pkey());
        }
    }
    return ret;
}

return_t crypto_key::add(EVP_PKEY* pkey, const char* kid, bool up_ref) {
    return_t ret = errorcode_t::success;
    crypto_key_object key(pkey, crypto_use_t::use_any, kid, nullptr);
    ret = add(key, up_ref);
    return ret;
}

return_t crypto_key::add(EVP_PKEY* pkey, const char* kid, crypto_use_t use, bool up_ref) {
    return_t ret = errorcode_t::success;
    crypto_key_object key(pkey, use, kid, nullptr);
    ret = add(key, up_ref);
    return ret;
}

void crypto_key::clear() {
    critical_section_guard guard(_lock);
    for (auto& pair : _key_map) {
        crypto_key_object& keyobj = pair.second;
        auto pkey = keyobj.get_pkey();
        if (pkey) {
            EVP_PKEY_free((EVP_PKEY*)pkey);
        }
        auto x509 = keyobj.get_x509();
        if (x509) {
            X509_free((X509*)x509);
        }
    }
    _key_map.clear();
}

size_t crypto_key::size() { return _key_map.size(); }

return_t crypto_key::append(crypto_key* source) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == source) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        critical_section_guard guard(_lock);
        critical_section_guard guard_source(source->_lock);
        for (auto& pair : _key_map) {
            const std::string& name = pair.first;
            crypto_key_object& keyobj = pair.second;
            EVP_PKEY_up_ref((EVP_PKEY*)keyobj.get_pkey());
            _key_map.insert(std::make_pair(name, keyobj));
        }
    }
    __finally2 {}
    return ret;
}

int crypto_key::addref() { return _shared.addref(); }

int crypto_key::release() { return _shared.delref(); }

void crypto_key::for_each(std::function<void(crypto_key_object*, void*)> fp_dump, void* param) {
    critical_section_guard guard(_lock);
    __try2 {
        if (nullptr == fp_dump) {
            __leave2;
        }

        for (auto& pair : _key_map) {
            crypto_key_object& keyobj = pair.second;
            fp_dump(&keyobj, param);
        }
    }
    __finally2 {}
}

void crypto_key::erase(const std::string& kid) {
    critical_section_guard guard(_lock);
    auto lbound = _key_map.lower_bound(kid);
    auto ubound = _key_map.upper_bound(kid);
    for (auto iter = lbound; iter != ubound;) {
        auto pkey = iter->second.get_pkey();
        _key_map.erase(iter++);
        EVP_PKEY_free((EVP_PKEY*)pkey);  // reference counter --
    }
}

crypto_kty_t ktyof_evp_pkey(crypto_key_object& key) { return ktyof_evp_pkey(key.get_pkey()); }

}  // namespace crypto
}  // namespace hotplace
