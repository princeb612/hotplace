/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/tls1/tls_advisor.hpp>
#include <sdk/net/tls1/tls_protection.hpp>
#include <sdk/net/tls1/tls_session.hpp>

namespace hotplace {
namespace net {

protection_context::protection_context() : _cipher_suite_hint(nullptr) {}

protection_context::protection_context(const protection_context& rhs) {
    _cipher_suites = rhs._cipher_suites;
    _signature_algorithms = rhs._signature_algorithms;
    _supported_groups = rhs._supported_groups;
    _supported_versions = rhs._supported_versions;
    _ec_point_formats = rhs._ec_point_formats;
    _cipher_suite_hint = rhs._cipher_suite_hint;
}

protection_context::protection_context(protection_context&& rhs) {
    clear();
    _cipher_suites = std::move(rhs._cipher_suites);
    _signature_algorithms = std::move(rhs._signature_algorithms);
    _supported_groups = std::move(rhs._supported_groups);
    _supported_versions = std::move(rhs._supported_versions);
    _ec_point_formats = std::move(rhs._ec_point_formats);
    _cipher_suite_hint = rhs._cipher_suite_hint;
}

void protection_context::add_cipher_suite(uint16 cs) { _cipher_suites.push_back(cs); }

void protection_context::add_signature_algorithm(uint16 sa) { _signature_algorithms.push_back(sa); }

void protection_context::add_supported_group(uint16 sg) { _supported_groups.push_back(sg); }

void protection_context::add_supported_version(uint16 sv) { _supported_versions.push_back(sv); }

void protection_context::add_ec_point_format(uint8 epf) { _ec_point_formats.push_back(epf); }

void protection_context::clear_cipher_suites() { _cipher_suites.clear(); }

void protection_context::clear_signature_algorithms() { _signature_algorithms.clear(); }

void protection_context::clear_supported_groups() { _supported_groups.clear(); }

void protection_context::clear_supported_versions() { _supported_versions.clear(); }

void protection_context::clear_ec_point_formats() { _ec_point_formats.clear(); }

void protection_context::for_each_cipher_suites(std::function<void(uint16, bool*)> fn) {
    bool test = false;
    for (auto item : _cipher_suites) {
        fn(item, &test);
        if (test) {
            break;
        }
    }
}

void protection_context::for_each_signature_algorithms(std::function<void(uint16, bool*)> fn) {
    bool test = false;
    for (auto item : _signature_algorithms) {
        fn(item, &test);
        if (test) {
            break;
        }
    }
}

void protection_context::for_each_supported_groups(std::function<void(uint16, bool*)> fn) {
    bool test = false;
    for (auto item : _supported_groups) {
        fn(item, &test);
        if (test) {
            break;
        }
    }
}

void protection_context::for_each_supported_versions(std::function<void(uint16, bool*)> fn) {
    bool test = false;
    for (auto item : _supported_versions) {
        fn(item, &test);
        if (test) {
            break;
        }
    }
}

void protection_context::for_each_ec_point_formats(std::function<void(uint8, bool*)> fn) {
    bool test = false;
    for (auto item : _ec_point_formats) {
        fn(item, &test);
        if (test) {
            break;
        }
    }
}

void protection_context::clear() {
    _cipher_suites.clear();
    _signature_algorithms.clear();
    _supported_groups.clear();
    _supported_versions.clear();
    _ec_point_formats.clear();
}

return_t protection_context::select_from(const protection_context& rhs) {
    return_t ret = errorcode_t::success;
    __try2 {
        clear();

        tls_advisor* tlsadvisor = tls_advisor::get_instance();

        uint16 selected_version = tls_10;
        {
            auto& versions = rhs._supported_versions;
            for (auto ver : versions) {
                if (tlsadvisor->is_kindof(tls_13, ver)) {
                    selected_version = ver;
                    break;
                } else if (tlsadvisor->is_kindof(tls_12, ver)) {
                    selected_version = ver;
                }
            }
            if (tls_10 == selected_version) {
                ret = errorcode_t::not_supported;
                __leave2;
            }
            add_supported_version(selected_version);
        }
        {
            for (auto cs : rhs._cipher_suites) {
                auto hint = tlsadvisor->hintof_cipher_suite(cs);
                // RFC 5246 mandatory TLS_RSA_WITH_AES_128_CBC_SHA
                if (hint && hint->support && tlsadvisor->is_kindof(hint->version, selected_version)) {
                    add_cipher_suite(cs);
                    set_cipher_suite(cs);
                    break;
                }
            }
            if (_cipher_suites.empty()) {
                ret = errorcode_t::not_found;
                __leave2;
            }
        }
        {
            // copy
            _signature_algorithms = rhs._signature_algorithms;
            _supported_groups = rhs._supported_groups;
        }
    }
    __finally2 {}
    return ret;
}

const tls_cipher_suite_t* protection_context::get_cipher_suite_hint() { return _cipher_suite_hint; }

void protection_context::set_cipher_suite(uint16 cs) {
    tls_advisor* tlsadvisor = tls_advisor::get_instance();
    auto hint = tlsadvisor->hintof_cipher_suite(cs);

    _cipher_suite = cs;
    _cipher_suite_hint = hint;
}

uint16 protection_context::get0_cipher_suite() {
    uint16 ret_value = 0;
    if (false == _cipher_suites.empty()) {
        ret_value = *_cipher_suites.begin();
    }
    return ret_value;
}

uint16 protection_context::get0_supported_version() {
    uint16 ret_value = 0;
    if (false == _supported_versions.empty()) {
        ret_value = *_supported_versions.begin();
    }
    return ret_value;
}

uint16 protection_context::select_signature_algorithm(crypto_kty_t kty) {
    uint16 ret_value = 0;
    tls_advisor* tlsadvisor = tls_advisor::get_instance();
    for (auto item : _signature_algorithms) {
        auto hint = tlsadvisor->hintof_signature_scheme(item);
        if (hint) {
            if (hint->pri && (hint->kty == kty)) {
                ret_value = item;
                break;
            }
        }
    }
    return ret_value;
}

}  // namespace net
}  // namespace hotplace
