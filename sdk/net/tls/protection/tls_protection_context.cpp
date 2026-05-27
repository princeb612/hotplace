/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_protection_context.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/crypto/advisor/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/evp_pkey.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_protection.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

protection_context::protection_context() : _cipher_suite(0) {}

protection_context::protection_context(const protection_context& other) {
    _cipher_suites = other._cipher_suites;
    _signature_algorithms = other._signature_algorithms;
    _supported_groups = other._supported_groups;
    _supported_versions = other._supported_versions;
    _ec_point_formats = other._ec_point_formats;
    _keyshare_groups = other._keyshare_groups;
    _keyshare_set = other._keyshare_set;
    _cipher_suite = other._cipher_suite;
}

protection_context::protection_context(protection_context&& other) {
    clear();
    _cipher_suites = std::move(other._cipher_suites);
    _signature_algorithms = std::move(other._signature_algorithms);
    _supported_groups = std::move(other._supported_groups);
    _supported_versions = std::move(other._supported_versions);
    _ec_point_formats = std::move(other._ec_point_formats);
    _keyshare_groups = std::move(other._keyshare_groups);
    _keyshare_set = std::move(other._keyshare_set);
    _cipher_suite = other._cipher_suite;
}

return_t protection_context::negotiate(tls_session* session, tls_version_t minspec, tls_version_t maxspec, uint16& cs, tls_version_t& tlsver) {
    return_t ret = errorcode_t::success;
    if (session) {
        cs = 0;
        tlsver = tls_version_t::unknown;

        // tls_advisor* tlsadvisor = tls_advisor::get_instance();
        auto& protection = session->get_tls_protection();
        auto& prot_context = protection.get_protection_context();
        auto nego_context = protection.get_protection_context();  // copy

        ret = prot_context.select_from(nego_context, session, minspec, maxspec);

        cs = prot_context.get0_cipher_suite();
        tlsver = prot_context.get0_supported_version();
    } else {
        ret = errorcode_t::invalid_parameter;
    }
    return ret;
}

void protection_context::add_cipher_suite(uint16 cs) { _cipher_suites.push_back(cs); }

void protection_context::add_signature_algorithm(uint16 sa) { _signature_algorithms.push_back(sa); }

void protection_context::add_supported_group(uint16 sg) { _supported_groups.push_back(sg); }

void protection_context::add_supported_version(tls_version_t sv) { _supported_versions.push_back(sv); }

void protection_context::add_ec_point_format(uint8 epf) { _ec_point_formats.push_back(epf); }

void protection_context::add_keyshare_group(uint16 group) {
    _keyshare_groups.push_back(group);
    _keyshare_set.insert(group);
}

void protection_context::clear_cipher_suites() { _cipher_suites.clear(); }

void protection_context::clear_signature_algorithms() { _signature_algorithms.clear(); }

void protection_context::clear_supported_groups() { _supported_groups.clear(); }

void protection_context::clear_supported_versions() { _supported_versions.clear(); }

void protection_context::clear_ec_point_formats() { _ec_point_formats.clear(); }

void protection_context::clear_keyshare_groups() {
    _keyshare_groups.clear();
    _keyshare_set.clear();
}

void protection_context::for_each_cipher_suites(std::function<void(uint16, bool*)> fn) const {
    bool cont = false;
    for (auto item : _cipher_suites) {
        fn(item, &cont);
        if (cont) {
            break;
        }
    }
}

void protection_context::for_each_signature_algorithms(std::function<void(uint16, bool*)> fn) const {
    bool cont = false;
    for (auto item : _signature_algorithms) {
        fn(item, &cont);
        if (cont) {
            break;
        }
    }
}

void protection_context::for_each_supported_groups(std::function<void(uint16, bool*)> fn) const {
    bool cont = false;
    for (auto item : _supported_groups) {
        fn(item, &cont);
        if (cont) {
            break;
        }
    }
}

void protection_context::for_each_supported_versions(std::function<void(tls_version_t, bool*)> fn) const {
    bool cont = false;
    for (auto item : _supported_versions) {
        fn(item, &cont);
        if (cont) {
            break;
        }
    }
}

void protection_context::for_each_ec_point_formats(std::function<void(uint8, bool*)> fn) const {
    bool cont = false;
    for (auto item : _ec_point_formats) {
        fn(item, &cont);
        if (cont) {
            break;
        }
    }
}

void protection_context::for_each_keyshare_groups(std::function<void(uint16, bool*)> fn) const {
    bool cont = false;
    for (auto item : _keyshare_set) {
        fn(item, &cont);
        if (cont) {
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
    clear_keyshare_groups();
}

return_t protection_context::select_from(const protection_context& other, tls_session* session, tls_version_t minspec, tls_version_t maxspec) {
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

        std::set<tls_version_t> specs;
        std::set<crypto_kty_t> certkty_set;
        std::set<uint32> certnid_set;
        std::map<uint16, std::list<uint16>> cs_map;

        // TLS specification
        for (uint16 t = tls_10; t <= tls_13; t++) {
            if ((minspec <= t) && (t <= maxspec)) {
                specs.insert((tls_version_t)t);
            }
        }

        {
            // check certificate type(s), see load_certificate
            auto& keys = tlsadvisor->get_certs();
            auto lambda = [&](crypto_key_object* k, void* param) -> void {
                auto pkey = k->get_pkey();
                hint_advisor_t hint;
                advisor->hintof_pkey(pkey, hint);
                certkty_set.insert(hint.kty);  // EC, RSA, DH, OKP, MLDSA
                certnid_set.insert(hint.nid);
#if defined DEBUG
                if (istraceable(trace_category_t::trace_category_net)) {
                    trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_tls_protection, [&](basic_stream& dbs) -> void {
                        std::string wellknown = namesof(&hint);
                        dbs.println(" ! " ANSI_ESCAPE "1;33m#certificate 0x%04x(%04u) %-7s %-5s %s" ANSI_ESCAPE "0m", hint.nid, hint.nid, k->get_desc().get_kid_cstr(),
                                    hint.hint_kty->name, wellknown.c_str());
                    });
                }
#endif
            };
            keys.for_each(lambda);
        }

        {
            for (auto cs : other._cipher_suites) {  // request
                auto hint = tlsadvisor->hintof_cipher_suite(cs);
                if (hint && (tls_flag_support & hint->flags)) {
                    {
                        // enforce minspec~maxspec
                        auto it = specs.find(hint->spec);
                        if (specs.end() == it) {
                            continue;
                        }
                    }
                    if (false == tlsadvisor->test_ciphersuite(cs)) {  // see set_ciphersuites
                        continue;
                    }

                    if (tls_13 != hint->spec) {
                        if (certkty_set.empty()) {
                            continue;
                        }
                        switch (hint->auth) {
                            case auth_rsa: {
                                // allow TLS_ECDHE_RSA if RSA certificate exist
                                auto iter = certkty_set.find(kty_rsa);
                                if (certkty_set.end() == iter) {
                                    continue;
                                }
                            } break;
                            case auth_ecdsa: {
                                // allow TLS_ECDHE_ECDSA if EC certificate exist
                                auto iter = certkty_set.find(kty_ec);
                                if (certkty_set.end() == iter) {
                                    continue;
                                }
                            } break;
                            default:
                                break;
                        }
                    }
#if defined DEBUG
                    if (istraceable(trace_category_t::trace_category_net)) {
                        trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_tls_protection, [&](basic_stream& dbs) -> void {
                            dbs.println(" ? " ANSI_ESCAPE "1;33m#ciphersuite 0x%04x(%04u) %s" ANSI_ESCAPE "0m", cs, cs, hint->name_iana);
                        });
                    }
#endif
                    cs_map[hint->spec].push_back(cs);
                }
            }
        }

        tls_version_t spec = unknown;
        {
            auto lambda_select_cs = [&](tls_version_t ver) -> bool {
                bool ret_value = false;
                for (auto cs : cs_map[ver]) {
                    spec = ver;
                    add_supported_version(ver);
                    add_cipher_suite(cs);
                    set_cipher_suite(cs);
                    ret_value = true;
#if defined DEBUG
                    if (istraceable(trace_category_t::trace_category_net)) {
                        auto hint = tlsadvisor->hintof_cipher_suite(cs);
                        trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_tls_protection, [&](basic_stream& dbs) -> void {
                            dbs.println(" ! " ANSI_ESCAPE "1;33m#supported version 0x%04x" ANSI_ESCAPE "0m", ver);
                            dbs.println(" ! " ANSI_ESCAPE "1;33m#ciphersuite 0x%04x(%04u) %s" ANSI_ESCAPE "0m", cs, cs, hint->name_iana);
                        });
                    }
#endif
                    break;
                }
                return ret_value;
            };

            bool test = false;
            test = lambda_select_cs(tls_13);
            if ((session_type_tls == session_type) || (session_type_dtls == session_type)) {  // not QUIC, QUIC2
                if (false == test) {
                    test = lambda_select_cs(tls_12);
                }
                if (false == test) {
                    test = lambda_select_cs(tls_11);
                }
                if (false == test) {
                    test = lambda_select_cs(tls_10);
                }
            }

            if (false == test) {
                ret = errorcode_t::handshake_failure;
                __leave2_trace(ret);
            }
        }

        {
            other.for_each_signature_algorithms([&](uint16 scheme, bool*) -> void {
                auto hint = advisor->hintof_sigscheme(scheme);
                if (hint && (tls_flag_support & hint->flags)) {
                    if (certnid_set.end() != certnid_set.find(hint->nid)) {
                        _signature_algorithms.push_back(scheme);
#if defined DEBUG
                        if (istraceable(trace_category_t::trace_category_net)) {
                            trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_tls_protection, [&](basic_stream& dbs) -> void {
                                dbs.println(" ! " ANSI_ESCAPE "1;33m#signature 0x%04x(%04u) %s" ANSI_ESCAPE "0m", scheme, scheme, hint->name);
                            });
                        }
#endif
                    }
                }
            });
        }

        {
            // _supported_groups

            other.for_each_supported_groups([&](uint16 group, bool*) -> void {
                auto hint = advisor->hintof_tls_group(group);
                if (hint && (tls_flag_support & hint->flags)) {
                    bool cond = true;
                    if (tlsadvisor->test_tls_group(group)) {
                        if (tls_flag_pqc & hint->flags) {
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
                            cond = (tls_13 == spec);
#else
                            cond = false;
#endif
                        }
                        if (cond) {
                            if (tls_flag_secure & hint->flags) {
                                _supported_groups.insert(_supported_groups.begin(), group);
                            } else {
                                _supported_groups.push_back(group);
                            }
                        }
                    }
                }
            });
        }

        {
            // deselect GREASE
            other.for_each_keyshare_groups([&](uint16 group, bool*) -> void {
                auto hint = advisor->hintof_tls_group(group);
                if (hint && (tls_flag_support & hint->flags)) {
                    if (tls_flag_secure & hint->flags) {
                        _keyshare_groups.insert(_keyshare_groups.begin(), group);
                    } else {
                        _keyshare_groups.push_back(group);
                    }
                    _keyshare_set.insert(group);
#if defined DEBUG
                    if (istraceable(trace_category_t::trace_category_net)) {
                        trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_tls_protection, [&](basic_stream& dbs) -> void {
                            dbs.println(" - " ANSI_ESCAPE "1;33m#keyshare 0x%04x(%04u) %s" ANSI_ESCAPE "0m", group, group, tlsadvisor->nameof_group(group).c_str());
                        });
                    }
#endif
                }
            });
        }
    }
    __finally2 {}
    return ret;
}

bool protection_context::select_keyshare(uint16 group) { return _keyshare_set.count(group) > 0; }

void protection_context::set_cipher_suite(uint16 cs) { _cipher_suite = cs; }

uint16 protection_context::get0_cipher_suite() {
    uint16 ret_value = 0;
    if (false == _cipher_suites.empty()) {
        ret_value = *_cipher_suites.begin();
    }
    return ret_value;
}

tls_version_t protection_context::get0_supported_version() {
    tls_version_t ret_value = tls_version_t::unknown;
    if (false == _supported_versions.empty()) {
        ret_value = *_supported_versions.begin();
    }
    return ret_value;
}

uint16 protection_context::get0_supported_group() {
    uint16 ret_value = 0;
    if (false == _supported_groups.empty()) {
        ret_value = *_supported_groups.begin();
    }
    return ret_value;
}

uint16 protection_context::get0_keyshare_group() {
    uint16 ret_value = 0;
    if (false == _keyshare_groups.empty()) {
        ret_value = *_keyshare_groups.begin();
    }
    return ret_value;
}

uint16 protection_context::select_signature_algorithm(crypto_kty_t kty) {
    uint16 ret_value = 0;
    auto advisor = crypto_advisor::get_instance();
    for (auto item : _signature_algorithms) {
        auto hint = advisor->hintof_sigscheme(item);
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
