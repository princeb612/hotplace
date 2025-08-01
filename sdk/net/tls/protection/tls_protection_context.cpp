/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/evp_key.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_protection.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

protection_context::protection_context() : _cipher_suite(0) {}

protection_context::protection_context(const protection_context& rhs) {
    _cipher_suites = rhs._cipher_suites;
    _signature_algorithms = rhs._signature_algorithms;
    _supported_groups = rhs._supported_groups;
    _supported_versions = rhs._supported_versions;
    _ec_point_formats = rhs._ec_point_formats;
    _cipher_suite = rhs._cipher_suite;
}

protection_context::protection_context(protection_context&& rhs) {
    clear();
    _cipher_suites = std::move(rhs._cipher_suites);
    _signature_algorithms = std::move(rhs._signature_algorithms);
    _supported_groups = std::move(rhs._supported_groups);
    _supported_versions = std::move(rhs._supported_versions);
    _ec_point_formats = std::move(rhs._ec_point_formats);
    _cipher_suite = rhs._cipher_suite;
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

void protection_context::for_each_cipher_suites(std::function<void(uint16, bool*)> fn) const {
    bool test = false;
    for (auto item : _cipher_suites) {
        fn(item, &test);
        if (test) {
            break;
        }
    }
}

void protection_context::for_each_signature_algorithms(std::function<void(uint16, bool*)> fn) const {
    bool test = false;
    for (auto item : _signature_algorithms) {
        fn(item, &test);
        if (test) {
            break;
        }
    }
}

void protection_context::for_each_supported_groups(std::function<void(uint16, bool*)> fn) const {
    bool test = false;
    for (auto item : _supported_groups) {
        fn(item, &test);
        if (test) {
            break;
        }
    }
}

void protection_context::for_each_supported_versions(std::function<void(uint16, bool*)> fn) const {
    bool test = false;
    for (auto item : _supported_versions) {
        fn(item, &test);
        if (test) {
            break;
        }
    }
}

void protection_context::for_each_ec_point_formats(std::function<void(uint8, bool*)> fn) const {
    bool test = false;
    for (auto item : _ec_point_formats) {
        fn(item, &test);
        if (test) {
            break;
        }
    }
}

void protection_context::clear() {
    clear_cipher_suites();
    clear_signature_algorithms();
    clear_supported_groups();
    clear_supported_versions();
    clear_ec_point_formats();
}

return_t protection_context::select_from(const protection_context& rhs, tls_session* session) {
    return_t ret = errorcode_t::success;
    __try2 {
        clear();

        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto session_type = session->get_type();

        crypto_advisor* advisor = crypto_advisor::get_instance();
        tls_advisor* tlsadvisor = tls_advisor::get_instance();

        std::set<crypto_kty_t> ktypes_set;
        std::map<uint16, uint16> tlsversion_map;
        std::map<uint16, std::list<uint16>> cs_map;

        for (auto ver : rhs._supported_versions) {
            bool is_tls13 = tlsadvisor->is_kindof_tls13(ver);
            tlsversion_map.insert({is_tls13 ? tls_13 : tls_12, ver});
        }

        {
            // check certificate type(s), see load_certificate
            auto& keys = tlsadvisor->get_keys();
            auto lambda = [&](crypto_key_object* k, void* param) -> void {
                auto pkey = k->get_pkey();
                auto kty = typeof_crypto_key(pkey);
                ktypes_set.insert(kty);
            };
            keys.for_each(lambda, nullptr);
        }

        {
            uint16 candidate = 0;

            for (auto cs : rhs._cipher_suites) {  // request
                auto hint = tlsadvisor->hintof_cipher_suite(cs);
                if (hint && (tls_flag_support & hint->flags)) {
                    if (false == tlsadvisor->test_ciphersuite(cs)) {  // see set_ciphersuites
                        continue;
                    }

                    if (tls_13 != hint->version) {
                        if (ktypes_set.empty()) {
                            ret = error_certificate;
                            break;
                        }
                        switch (hint->auth) {
                            case auth_rsa: {
                                // allow TLS_ECDHE_RSA if RSA certificate exist
                                auto iter = ktypes_set.find(kty_rsa);
                                if (ktypes_set.end() == iter) {
                                    continue;
                                }
                            } break;
                            case auth_ecdsa: {
                                // allow TLS_ECDHE_ECDSA if EC certificate exist
                                auto iter = ktypes_set.find(kty_ec);
                                if (ktypes_set.end() == iter) {
                                    continue;
                                }
                            } break;
                        }
                    }
#if defined DEBUG
                    if (istraceable(trace_category_net)) {
                        basic_stream dbs;
                        dbs.println(" ? \e[1;33m# 0x%02x %s\e[0m", cs, hint->name_iana);
                        trace_debug_event(trace_category_net, trace_event_tls_protection, &dbs);
                    }
#endif
                    cs_map[hint->version].push_back(cs);
                }
            }
        }
        if (errorcode_t::success != ret) {
            __leave2;
        }

        {
            auto lambda = [&](tls_version_t ver) -> bool {
                bool ret_value = false;
                for (auto cs : cs_map[ver]) {
                    add_supported_version(ver);
                    add_cipher_suite(cs);
                    set_cipher_suite(cs);
                    ret_value = true;
#if defined DEBUG
                    if (istraceable(trace_category_net)) {
                        auto hint = tlsadvisor->hintof_cipher_suite(cs);
                        basic_stream dbs;
                        dbs.println(" ! \e[1;33m# 0x%02x %s\e[0m", cs, hint->name_iana);
                        trace_debug_event(trace_category_net, trace_event_tls_protection, &dbs);
                    }
#endif
                    break;
                }
                return ret_value;
            };

            bool test = false;
            test = lambda(tls_13);
            if ((session_type_tls == session_type) || (session_type_dtls == session_type)) {  // not QUIC, QUIC2
                if (false == test) {
                    test = lambda(tls_12);
                }
                if (false == test) {
                    test = lambda(tls_11);
                }
                if (false == test) {
                    test = lambda(tls_10);
                }
            }

            if (false == test) {
                session->push_alert(from_server, tls_alertlevel_fatal, tls_alertdesc_handshake_failure);
                session->reset_session_status();
                ret = errorcode_t::error_handshake;
                __leave2;
            }
        }

        {
            // copy
            _signature_algorithms = rhs._signature_algorithms;

            auto lambda_supported_groups = [&](uint16 group, bool*) -> void {
                auto hint = tlsadvisor->hintof_tls_group(group);
                if (hint && (tls_flag_support & hint->flags)) {
                    _supported_groups.push_back(group);
                }
            };
            rhs.for_each_supported_groups(lambda_supported_groups);
        }
    }
    __finally2 {}
    return ret;
}

void protection_context::set_cipher_suite(uint16 cs) { _cipher_suite = cs; }

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
            if ((tls_flag_support & hint->flags) && (hint->kty == kty)) {
                ret_value = item;
                break;
            }
        }
    }
    return ret_value;
}

}  // namespace net
}  // namespace hotplace
