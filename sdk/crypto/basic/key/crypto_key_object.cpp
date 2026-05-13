/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   crypto_key_object.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/crypto_key.hpp>

namespace hotplace {
namespace crypto {

crypto_key_object::crypto_key_object() : _pkey(nullptr), _x509(nullptr) {}

crypto_key_object::crypto_key_object(const crypto_key_object& other) : crypto_key_object() { *this = other; }

crypto_key_object::crypto_key_object(crypto_key_object&& other) : crypto_key_object() { *this = std::move(other); }

crypto_key_object::crypto_key_object(EVP_PKEY* key, const keydesc& desc) : crypto_key_object() {
    if (key) {
        EVP_PKEY_up_ref(key);
        _pkey = key;
    }

    _desc = desc;
}

crypto_key_object::crypto_key_object(EVP_PKEY* key, keydesc&& desc) : crypto_key_object() {
    if (key) {
        EVP_PKEY_up_ref(key);
        _pkey = key;
    }

    _desc = std::move(desc);
}

crypto_key_object::crypto_key_object(EVP_PKEY* key, X509* x509, const keydesc& desc) : crypto_key_object() {
    if (key) {
        EVP_PKEY_up_ref(key);
        _pkey = key;
    }
    if (x509) {
        X509_up_ref(x509);
        _x509 = x509;
    }

    _desc = desc;
}

crypto_key_object::crypto_key_object(EVP_PKEY* key, X509* x509, keydesc&& desc) : crypto_key_object() {
    if (key) {
        EVP_PKEY_up_ref(key);
        _pkey = key;
    }
    if (x509) {
        X509_up_ref(x509);
        _x509 = x509;
    }

    _desc = std::move(desc);
}

crypto_key_object::~crypto_key_object() { release(); }

void crypto_key_object::release() {
    if (_pkey) {
        EVP_PKEY_free(_pkey);
    }
    if (_x509) {
        X509_free(_x509);
    }
}

crypto_key_object& crypto_key_object::operator=(const crypto_key_object& other) {
    release();

    if (other._pkey) {
        _pkey = other._pkey;
        EVP_PKEY_up_ref(_pkey);
    }
    if (other._x509) {
        _x509 = other._x509;
        X509_up_ref(_x509);
    }

    _desc = other._desc;

    return *this;
}

crypto_key_object& crypto_key_object::operator=(crypto_key_object&& other) {
    std::swap(_pkey, other._pkey);
    std::swap(_x509, other._x509);
    std::swap(_desc, other._desc);
    return *this;
}

const keydesc& crypto_key_object::get_desc() const { return _desc; }

const EVP_PKEY* crypto_key_object::get_pkey() const { return _pkey; }

const X509* crypto_key_object::get_x509() const { return _x509; }

uint16 crypto_key_object::get_group() { return _desc.get_group(); }

crypto_key_object& crypto_key_object::set_desc(const keydesc& desc) {
    _desc = desc;
    return *this;
}

crypto_key_object& crypto_key_object::set_desc(keydesc&& desc) {
    _desc = std::move(desc);
    return *this;
}

crypto_key_object& crypto_key_object::set_alg(const char* alg) {
    _desc.set_alg(alg);
    return *this;
}

crypto_key_object& crypto_key_object::set_use(crypto_use_t use) {
    _desc.set_use(use);
    return *this;
}

crypto_key_object& crypto_key_object::set_group(uint16 group) {
    _desc.set_group(group);
    return *this;
}

}  // namespace crypto
}  // namespace hotplace
