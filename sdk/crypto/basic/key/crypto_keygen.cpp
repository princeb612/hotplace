/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   crypto_keygen.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/base16.hpp>
#include <hotplace/sdk/base/basic/base64.hpp>
#include <hotplace/sdk/base/basic/variant.hpp>
#include <hotplace/sdk/base/nostd/enumclass.hpp>
#include <hotplace/sdk/base/nostd/exception.hpp>
#include <hotplace/sdk/crypto/advisor/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/crypto_keychain.hpp>
#include <hotplace/sdk/crypto/basic/crypto_keygen.hpp>

namespace hotplace {
namespace crypto {

crypto_keygen::crypto_keygen(crypto_key* key, const std::string& name, encoding_t encoding) : _key(key), _name(name), _encoding(encoding) {
    if (key) {
        key->addref();
    } else {
        throw exception(errorcode_t::not_specified);
    }
}

crypto_keygen& crypto_keygen::set(keydesc&& desc) {
    _desc = std::forward<keydesc>(desc);
    return *this;
}

crypto_keygen& crypto_keygen::set(crypt_item_t item, binary_t&& value) {
    critical_section_guard guard(_lock);
    _map.emplace(item, std::forward<binary_t>(value));
    return *this;
}

crypto_keygen& crypto_keygen::set(crypt_item_t item, const char* value) {
    if (value) {
        variant vt(value, strlen(value));

        critical_section_guard guard(_lock);
        _vtmap.emplace(item, std::move(vt));
    }
    return *this;
}

crypto_keygen& crypto_keygen::set(crypt_item_t item, bool value) {
    variant vt(value);

    critical_section_guard guard(_lock);
    _vtmap.emplace(item, std::move(vt));
    return *this;
}

crypto_keygen& crypto_keygen::set(const char* item, binary_t&& value) {
    if (item) {
        auto advisor = crypto_advisor::get_instance();
        auto item_t = advisor->itemof(item);
        set(item_t, std::forward<binary_t>(value));
    }
    return *this;
}

crypto_keygen& crypto_keygen::set(const char* item, const char* value) {
    if (item && value) {
        auto advisor = crypto_advisor::get_instance();
        auto item_t = advisor->itemof(item);
        set(item_t, value);
    }
    return *this;
}

crypto_keygen& crypto_keygen::set(const char* item, bool value) {
    if (item) {
        auto advisor = crypto_advisor::get_instance();
        auto item_t = advisor->itemof(item);
        set(item_t, value);
    }
    return *this;
}

crypto_keygen& crypto_keygen::gen() {
    auto advisor = crypto_advisor::get_instance();
    auto nid = advisor->nidof_name(_name);

    crypto_keychain keychain;
    keychain.add(_key, nid, std::move(_desc));

    return *this;
}

crypto_keygen& crypto_keygen::build() {
    auto advisor = crypto_advisor::get_instance();
    auto kty = advisor->ktyof_name(_name);
    auto nid = advisor->nidof_name(_name);
    crypto_keychain keychain;
    critical_section_guard guard(_lock);

    auto os2b = [&](const char* input, size_t size, binary_t& output) -> void {
        if (input) {
            switch (_encoding) {
                case encoding_t::encoding_base16: {
                    output = std::move(base16_decode(input, size));
                } break;
                case encoding_t::encoding_base16rfc: {
                    output = std::move(base16_decode_rfc(std::string(input)));
                } break;
                case encoding_t::encoding_base64:
                case encoding_t::encoding_base64url: {
                    output = std::move(base64_decode(input, size, _encoding));
                } break;
                default: {
                } break;
            }
        }
    };

    auto finder_binary = [&](crypt_item_t item, binary_t& value) -> bool {
        bool ret = false;
        auto iter = _map.find(item);
        if (_map.end() != iter) {
            value = std::move(iter->second);
            ret = true;
        } else {
            auto vtiter = _vtmap.find(item);
            if (_vtmap.end() != vtiter) {
                variant vt;
                vt = std::move(vtiter->second);
                if (vartype_t::TYPE_STRING == vt.type()) {
                    os2b(vt.content().data.str, vt.size(), value);
                    ret = true;
                }
            }
        }
        return ret;
    };
    auto finder_bool = [&](crypt_item_t item, bool& value) -> bool {
        bool ret = false;
        auto vtiter = _vtmap.find(item);
        if (_vtmap.end() != vtiter) {
            variant vt;
            vt = std::move(vtiter->second);
            if (vartype_t::TYPE_BOOL == vt.type()) {
                value = vt.content().data.b;
                ret = true;
            }
        }
        return ret;
    };

    bool check = false;
    switch (kty) {
        case kty_dh: {
            binary_t bin_x;
            binary_t bin_y;
            finder_binary(crypt_item_t::dh_x, bin_x);
            check = finder_binary(crypt_item_t::dh_y, bin_y);
            if (check) {
                keychain.add_dh(_key, nid, bin_y, bin_x, std::move(_desc));
            } else {
                binary_t bin_p;
                binary_t bin_q;
                binary_t bin_g;
                finder_binary(crypt_item_t::dh_p, bin_p);
                finder_binary(crypt_item_t::dh_q, bin_q);
                finder_binary(crypt_item_t::dh_g, bin_g);
                keychain.add_dh(_key, nid, bin_p, bin_q, bin_g, bin_x, std::move(_desc));
            }
        } break;
        case kty_dsa: {
            binary_t bin_x;
            binary_t bin_y;
            binary_t bin_p;
            binary_t bin_q;
            binary_t bin_g;
            finder_binary(crypt_item_t::dsa_y, bin_y);
            finder_binary(crypt_item_t::dsa_x, bin_x);
            finder_binary(crypt_item_t::dsa_p, bin_p);
            finder_binary(crypt_item_t::dsa_q, bin_q);
            finder_binary(crypt_item_t::dsa_g, bin_g);
            keychain.add_dsa(_key, nid, bin_y, bin_x, bin_p, bin_q, bin_g, std::move(_desc));
        } break;
        case kty_ec: {
            binary_t bin_d;
            finder_binary(crypt_item_t::ec_d, bin_d);

            binary_t bin_x;
            check = finder_binary(crypt_item_t::ec_x, bin_x);
            if (check) {
                binary_t bin_y;
                check = finder_binary(crypt_item_t::ec_y, bin_y);
                if (check) {
                    keychain.add_ec(_key, _name.c_str(), bin_x, bin_y, bin_d, std::move(_desc));
                } else {
                    bool ysign = true;
                    check = finder_bool(crypt_item_t::ec_ybit, ysign);
                    if (check) {
                        keychain.add_ec_compressed(_key, _name.c_str(), bin_x, ysign, bin_d, std::move(_desc));
                    }
                }
            } else {
                binary_t bin_pub;
                check = finder_binary(crypt_item_t::ec_pub_uncompressed, bin_pub);
                if (check) {
                    keychain.add_ec_uncompressed(_key, _name.c_str(), bin_pub, bin_d, std::move(_desc));
                }
            }
        } break;
        case kty_oct: {
            binary_t bin_k;
            finder_binary(crypt_item_t::k, bin_k);
            keychain.add_oct(_key, bin_k, std::move(_desc));
        } break;
        case kty_okp: {
            binary_t bin_d;
            finder_binary(crypt_item_t::ec_d, bin_d);

            binary_t bin_x;
            check = finder_binary(crypt_item_t::ec_x, bin_x);
            if (check) {
                keychain.add_okp(_key, _name.c_str(), bin_x, bin_d, std::move(_desc));
            }
        } break;
        case kty_rsa:
        case kty_rsapss: {
            binary_t bin_n;
            binary_t bin_e;
            binary_t bin_d;
            finder_binary(crypt_item_t::rsa_n, bin_n);
            finder_binary(crypt_item_t::rsa_e, bin_e);
            finder_binary(crypt_item_t::rsa_d, bin_d);

            keychain.add_rsa(_key, nid, bin_n, bin_e, bin_d, std::move(_desc));
        } break;
        case kty_mldsa:
        case kty_mlkem:
        case kty_slhdsa: {
        } break;
        default: {
        } break;
    }

    _map.clear();
    _vtmap.clear();
    return *this;
}

}  // namespace crypto
}  // namespace hotplace
