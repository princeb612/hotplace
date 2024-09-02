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

cose_recipients::cose_recipients() : _upperlayer(nullptr) {}

cose_recipients::~cose_recipients() { clear(); }

cose_recipient& cose_recipients::add(cose_recipient* recipient) {
    recipient->set_upperlayer(get_upperlayer());
    std::list<cose_recipient*>::iterator iter = _recipients.insert(_recipients.end(), recipient);
    return **iter;
}

cose_recipients& cose_recipients::clear() {
    for (cose_recipient* recipient : _recipients) {
        delete recipient;
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
        for (cose_recipient* recipient : _recipients) {
            recipient->for_each(for_each_handler, userdata);
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
    for (cose_recipient* recipient : _recipients) {
        ret = recipient->finditem(key, value, scope);
        if (errorcode_t::success == ret) {
            break;
        }
    }
    return ret;
}

return_t cose_recipients::finditem(int key, std::string& value, int scope) {
    return_t ret = errorcode_t::not_found;
    for (cose_recipient* recipient : _recipients) {
        ret = recipient->finditem(key, value, scope);
        if (errorcode_t::success == ret) {
            break;
        }
    }
    return ret;
}

return_t cose_recipients::finditem(int key, binary_t& value, int scope) {
    return_t ret = errorcode_t::not_found;
    for (cose_recipient* recipient : _recipients) {
        ret = recipient->finditem(key, value, scope);
        if (errorcode_t::success == ret) {
            break;
        }
    }
    return ret;
}

cbor_array* cose_recipients::cbor() {
    cbor_array* object = new cbor_array;
    for (cose_recipient* recipient : _recipients) {
        *object << recipient->cbor();
    }
    return object;
}

}  // namespace crypto
}  // namespace hotplace
