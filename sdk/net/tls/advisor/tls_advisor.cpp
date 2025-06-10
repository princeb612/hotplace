/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/basic/binary.hpp>
#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/base/pattern/aho_corasick.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/evp_key.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_alpn.hpp>
#include <sdk/net/tls/tls/tls.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

hash_algorithm_t algof_mac(const tls_cipher_suite_t* info) {
    hash_algorithm_t alg = hash_alg_unknown;
    if (info) {
        alg = info->mac;
        switch (alg) {
            case md5:
            case sha1:
                // insecure algorithm promotion
                alg = sha2_256;
                break;
            default:
                break;
        }
    }
    return alg;
}

tls_advisor tls_advisor::_instance;

tls_advisor* tls_advisor::get_instance() {
    if (false == _instance._load) {
        critical_section_guard guard(_instance._lock);
        if (false == _instance._load) {
            _instance.load_resource();
            _instance._load = true;
        }
    }
    return &_instance;
}

tls_advisor::tls_advisor() : _load(false) {}

tls_advisor::~tls_advisor() {}

void tls_advisor::load_resource() {
    load_tls_parameters();
    load_tls_extensiontype_values();
    load_tls_quic();
    load_tls_aead_parameters();

    load_tls_version();
    load_etc();
}

void tls_advisor::load_tls_parameters() {
    // code, name
    for (auto i = 0; i < sizeof_tls_alert_level_codes; i++) {
        auto item = tls_alert_level_codes + i;
        _alert_level_codes.insert({item->code, item});
    }
    for (auto i = 0; i < sizeof_tls_alert_codes; i++) {
        auto item = tls_alert_codes + i;
        _alert_codes.insert({item->code, item});
    }
    for (auto i = 0; i < sizeof_tls_cipher_suites; i++) {
        auto item = tls_cipher_suites + i;
        _cipher_suite_codes.insert({item->code, item});
        if (item->name_iana) {
            _cipher_suite_names.insert({item->name_iana, item});
        }
        if (item->name_ossl) {
            _cipher_suite_names.insert({item->name_ossl, item});
        }
    }
    for (auto i = 0; i < sizeof_tls_content_type_codes; i++) {
        auto item = tls_content_type_codes + i;
        _content_type_codes.insert({item->code, item});
    }
    for (auto i = 0; i < sizeof_tls_ec_curve_type_codes; i++) {
        auto item = tls_ec_curve_type_codes + i;
        _ec_curve_type_codes.insert({item->code, item});
    }
    for (auto i = 0; i < sizeof_tls_ec_point_format_codes; i++) {
        auto item = tls_ec_point_format_codes + i;
        _ec_point_format_codes.insert({item->code, item});
        _ec_point_format_names.insert({item->desc, item});
    }
    for (auto i = 0; i < sizeof_tls_handshake_type_codes; i++) {
        auto item = tls_handshake_type_codes + i;
        _handshake_type_codes.insert({item->code, item});
    }
    for (auto i = 0; i < sizeof_tls_kdf_id_codes; i++) {
        auto item = tls_kdf_id_codes + i;
        _kdf_id_codes.insert({item->code, item});
    }
    for (auto i = 0; i < sizeof_tls_psk_keyexchange_codes; i++) {
        auto item = tls_psk_keyexchange_codes + i;
        _psk_keyexchange_codes.insert({item->code, item});
        _psk_keyexchange_names.insert({item->desc, item});
    }
    for (auto i = 0; i < sizeof_tls_sig_schemes; i++) {
        auto item = tls_sig_schemes + i;
        _sig_scheme_codes.insert({item->code, item});
        _sig_scheme_names.insert({item->name, item});
    }
    for (auto i = 0; i < sizeof_tls_groups; i++) {
        auto item = tls_groups + i;
        _supported_group_codes.insert({item->code, item});
        _supported_group_names.insert({item->name, item});
        _supported_group_nids.insert({item->nid, item});
    }
}

void tls_advisor::load_tls_extensiontype_values() {
    // compression_alg_code
    for (auto i = 0; i < sizeof_tls_compression_alg_codes; i++) {
        auto item = tls_compression_alg_codes + i;
        _compression_alg_codes.insert({item->code, item});
        _compression_alg_names.insert({item->desc, item});
    }
    for (auto i = 0; i < sizeof_tls_extension_type_codes; i++) {
        auto item = tls_extension_type_codes + i;
        _extension_type_codes.insert({item->code, item});
    }
    for (auto i = 0; i < sizeof_tls_cert_status_type_codes; i++) {
        auto item = tls_cert_status_type_codes + i;
        _cert_status_type_codes.insert({item->code, item});
    }
}

void tls_advisor::load_tls_quic() {
    for (auto i = 0; i < sizeof_tls_quic_trans_param_codes; i++) {
        auto item = tls_quic_trans_param_codes + i;
        _quic_trans_param_codes.insert({item->code, item});
    }
    for (auto i = 0; i < sizeof_tls_quic_frame_type_codes; i++) {
        auto item = tls_quic_frame_type_codes + i;
        _quic_frame_type_codes.insert({item->code, item});
    }
    for (auto i = 0; i < sizeof_tls_quic_trans_error_codes; i++) {
        auto item = tls_quic_trans_error_codes + i;
        _quic_trans_error_codes.insert({item->code, item});
    }
    for (auto i = 0; i < sizeof_tls_quic_packet_type_codes; i++) {
        auto item = tls_quic_packet_type_codes + i;
        _quic_packet_type_codes.insert({item->code, item});
    }
}

void tls_advisor::load_tls_aead_parameters() {
    for (auto i = 0; i < sizeof_tls_aead_alg_codes; i++) {
        auto item = tls_aead_alg_codes + i;
        _aead_alg_codes.insert({item->code, item});
    }
}

void tls_advisor::load_tls_version() {
    // 0x0304
    //  RFC 8446
    //   4.1.2.  Client Hello - see legacy_version
    //   4.2.1.  Supported Versions
    //   5.1.  Record Layer
    //   9.2.  Mandatory-to-Implement Extensions

    for (auto i = 0; i < sizeof_tls_version_hint; i++) {
        auto item = tls_version_hint + i;
        _tls_version.insert({item->code, item});
    }
}

void tls_advisor::load_etc() {
    for (auto i = 0; i < sizeof_tls_session_status_codes; i++) {
        auto item = tls_session_status_codes + i;
        _session_status_codes.insert({item->code, item});
    }
}

const tls_cipher_suite_t* tls_advisor::hintof_cipher_suite(uint16 code) {
    const tls_cipher_suite_t* ret_value = nullptr;
    auto iter = _cipher_suite_codes.find(code);
    if (_cipher_suite_codes.end() != iter) {
        ret_value = iter->second;
    }
    return ret_value;
}

const tls_cipher_suite_t* tls_advisor::hintof_cipher_suite(const std::string& name) {
    const tls_cipher_suite_t* ret_value = nullptr;
    auto iter = _cipher_suite_names.find(name);
    if (_cipher_suite_names.end() != iter) {
        ret_value = iter->second;
    }
    return ret_value;
}

const hint_cipher_t* tls_advisor::hintof_cipher(uint16 code) {
    const hint_cipher_t* ret_value = nullptr;
    auto iter = _cipher_suite_codes.find(code);
    if (_cipher_suite_codes.end() != iter) {
        crypto_advisor* advisor = crypto_advisor::get_instance();
        auto hint_cs = iter->second;
        ret_value = advisor->hintof_cipher(hint_cs->scheme);
    }
    return ret_value;
}

const hint_blockcipher_t* tls_advisor::hintof_blockcipher(uint16 code) {
    const hint_blockcipher_t* ret_value = nullptr;
    auto iter = _cipher_suite_codes.find(code);
    if (_cipher_suite_codes.end() != iter) {
        crypto_advisor* advisor = crypto_advisor::get_instance();
        auto hint_cs = iter->second;
        ret_value = advisor->hintof_blockcipher(hint_cs->scheme);
    }
    return ret_value;
}

void tls_advisor::enum_cipher_suites(std::function<void(const tls_cipher_suite_t*)> fn) {
    for (auto i = 0; i < sizeof_tls_cipher_suites; i++) {
        auto item = tls_cipher_suites + i;
        if (item->flags & tls_flag_support) {
            fn(item);
        }
    }
}

bool tls_advisor::is_kindof_cbc(uint16 code) {
    bool ret = false;
    auto iter = _cipher_suite_codes.find(code);
    if (_cipher_suite_codes.end() != iter) {
        auto item = iter->second;
        crypto_advisor* advisor = crypto_advisor::get_instance();
        auto hint_cipher = advisor->hintof_cipher(item->scheme);
        ret = (cbc == typeof_mode(hint_cipher));
    }
    return ret;
}

const hint_digest_t* tls_advisor::hintof_digest(uint16 code) {
    const hint_digest_t* ret_value = nullptr;
    auto hint_alg = hintof_cipher_suite(code);
    if (hint_alg) {
        crypto_advisor* advisor = crypto_advisor::get_instance();
        ret_value = advisor->hintof_digest(hint_alg->mac);
    }
    return ret_value;
}

const tls_sig_scheme_t* tls_advisor::hintof_signature_scheme(uint16 code) {
    const tls_sig_scheme_t* ret_value = nullptr;
    auto iter = _sig_scheme_codes.find(code);
    if (_sig_scheme_codes.end() != iter) {
        ret_value = iter->second;
    }
    return ret_value;
}

void tls_advisor::enum_signature_scheme(std::function<void(const tls_sig_scheme_t*)> func) {
    if (func) {
        for (auto item : _sig_scheme_codes) {
            func(item.second);
        }
    }
}

const tls_group_t* tls_advisor::hintof_tls_group(uint16 code) {
    const tls_group_t* ret_value = nullptr;
    auto iter = _supported_group_codes.find(code);
    if (_supported_group_codes.end() != iter) {
        ret_value = iter->second;
    }
    return ret_value;
}

const tls_group_t* tls_advisor::hintof_tls_group(const std::string& name) {
    const tls_group_t* ret_value = nullptr;
    auto iter = _supported_group_names.find(name);
    if (_supported_group_names.end() != iter) {
        ret_value = iter->second;
    }
    return ret_value;
}

const tls_group_t* tls_advisor::hintof_tls_group_nid(uint32 nid) {
    const tls_group_t* ret_value = nullptr;
    auto iter = _supported_group_nids.find(nid);
    if (_supported_group_nids.end() != iter) {
        ret_value = iter->second;
    }
    return ret_value;
}

void tls_advisor::enum_tls_group(std::function<void(const tls_group_t*)> func) {
    if (func) {
        for (auto item : _supported_group_codes) {
            func(item.second);
        }
    }
}

hash_algorithm_t tls_advisor::hash_alg_of(uint16 code) {
    hash_algorithm_t alg = hash_alg_unknown;
    const tls_cipher_suite_t* hint_tls_alg = hintof_cipher_suite(code);
    if (hint_tls_alg) {
        alg = hint_tls_alg->mac;
    }
    return alg;
}

// etc

const tls_version_hint_t* tls_advisor::hintof_tls_version(uint16 code) {
    const tls_version_hint_t* ret_value = nullptr;
    auto iter = _tls_version.find(code);
    if (_tls_version.end() != iter) {
        ret_value = iter->second;
    }
    return ret_value;
}

std::string tls_advisor::tls_version_string(uint16 code) {
    std::string value;
    auto iter = _tls_version.find(code);
    if (_tls_version.end() != iter) {
        auto item = iter->second;
        value = item->name;
    }
    return value;
}

std::string tls_advisor::compression_method_string(uint8 code) {
    std::string value;
    if (0 == code) {
        value = "null";
    } else if (1 == code) {
        value = "deflate";  // TLS 1.3 deprecated
        /**
         * RFC 3749 2.1.  DEFLATE Compression
         * RFC 5246 6.2.2.  Record Compression and Decompression
         *
         * RFC 8446 4.1.2.  Client Hello
         *   legacy_compression_methods
         *     ...
         *     For every TLS 1.3 ClientHello, this vector MUST contain exactly one byte, set to zero, which corresponds to
         *     the "null" compression method in prior versions of TLS.
         *     ...
         *     If a TLS 1.3 ClientHello is received with any other value in this field, the server MUST abort the handshake with an "illegal_parameter" alert.
         *     ...
         *
         * cf. CRIME attack (Compression Ratio Info-leak Made Easy)
         *     client-side attack
         *     server refuse 0x01 (deflate)
         */
    }
    return value;
}

std::string tls_advisor::sni_nametype_string(uint16 code) {
    std::string value;
    if (0 == code) {
        value = "hostname";
    }
    return value;
}

std::string tls_advisor::quic_packet_type_string(uint8 code) {
    std::string value;
    auto iter = _quic_packet_type_codes.find(code);
    if (_quic_packet_type_codes.end() != iter) {
        auto item = iter->second;
        value = item->desc;
    }
    return value;
}

bool tls_advisor::is_kindof_tls13(uint16 ver) {
    bool ret = false;
    auto hint = hintof_tls_version(ver);
    ret = (hint && hint->spec == tls_13);
    return ret;
}

bool tls_advisor::is_kindof_tls12(uint16 ver) {
    bool ret = false;
    auto hint = hintof_tls_version(ver);
    ret = (hint && hint->spec == tls_12);
    return ret;
}

bool tls_advisor::is_kindof_tls(uint16 ver) {
    bool ret = false;
    auto hint = hintof_tls_version(ver);
    ret = (hint && (hint->flags & flag_kindof_tls));
    return ret;
}

bool tls_advisor::is_kindof_dtls(uint16 ver) {
    bool ret = false;
    auto hint = hintof_tls_version(ver);
    ret = (hint && (0 == hint->flags & flag_kindof_tls));
    return ret;
}

bool tls_advisor::is_kindof(uint16 lhs, uint16 rhs) {
    bool ret = false;
    auto lhint = hintof_tls_version(lhs);
    auto rhint = hintof_tls_version(rhs);
    if (lhint && rhint) {
        if (lhs == rhs || lhint->spec == rhs || rhint->spec == lhs) {
            ret = true;
        }
    }
    return ret;
}

std::string tls_advisor::nameof_tls_flow(tls_flow_t flow) {
    std::string value;
    switch (flow) {
        case tls_flow_1rtt: {
            value = "1-RTT";
        } break;
        case tls_flow_0rtt: {
            value = "0-RTT";
        } break;
        case tls_flow_hello_retry_request: {
            value = "HelloRetryRequest";
        } break;
        case tls_flow_renegotiation: {
            value = "renegotiation";
        } break;
    }
    return value;
}

std::string tls_advisor::session_status_string(uint32 status) {
    std::string value;
    auto iter = _session_status_codes.find(status);
    if (_session_status_codes.end() != iter) {
        auto item = iter->second;
        value = item->desc;
    }
    return value;
}

void tls_advisor::enum_session_status_string(uint32 status, std::function<void(const char*)> func) {
    if (func) {
        for (const auto& item : _session_status_codes) {
            if (status & item.first) {
                func(item.second->desc);
            }
        }
    }
}

std::string tls_advisor::nameof_direction(tls_direction_t dir, bool longname) {
    std::string value;
    switch (dir) {
        case from_client: {
            if (longname) {
                value = "client->server";
            } else {
                value = "client";
            }
        } break;
        case from_server: {
            if (longname) {
                value = "server->client";
            } else {
                value = "server";
            }
        } break;
        case from_any: {
            value = "any";
        } break;
    }
    return value;
}

crypto_key& tls_advisor::get_keys() { return _keys; }

const EVP_PKEY* tls_advisor::get_key(tls_session* session, const char* kid) {
    const EVP_PKEY* ret_value = nullptr;
    __try2 {
        if (nullptr == session || nullptr == kid) {
            __leave2;
        }

        auto& protection = session->get_tls_protection();

        auto kty = kty_unknown;
        auto cs = protection.get_cipher_suite();
        auto hint = hintof_cipher_suite(cs);
        switch (hint->auth) {
            case auth_rsa:
                kty = kty_rsa;
                break;
            case auth_ecdsa:
                kty = kty_ec;
                break;
            default:
                break;
        }

        ret_value = protection.get_keyexchange().find(kid, kty);
        if (nullptr == ret_value) {
            ret_value = get_keys().find(kid, kty);
        }
    }
    __finally2 {}
    return ret_value;
}

const X509* tls_advisor::get_cert(tls_session* session, const char* kid) {
    const X509* ret_value = nullptr;
    __try2 {
        if (nullptr == session || nullptr == kid) {
            __leave2;
        }

        auto& protection = session->get_tls_protection();

        auto kty = kty_unknown;
        auto cs = protection.get_cipher_suite();
        auto hint = hintof_cipher_suite(cs);
        switch (hint->auth) {
            case auth_rsa:
                kty = kty_rsa;
                break;
            case auth_ecdsa:
                kty = kty_ec;
                break;
            default:
                break;
        }

        ret_value = protection.get_keyexchange().find_x509(kid, kty);
        if (nullptr == ret_value) {
            ret_value = get_keys().find_x509(kid, kty);
        }
    }
    __finally2 {}
    return ret_value;
}

return_t tls_advisor::enable_alpn(const char* prot) {
    return_t ret = errorcode_t::success;
    __try2 {
        _prot.clear();
        if (prot) {
            size_t size = strlen(prot);
            binary_append(_prot, uint8(size));
            binary_append(_prot, prot, size);
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_advisor::negotiate_alpn(tls_session* session, const byte_t* alpn, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (_prot.empty()) {
            __leave2;
        }
        if ((nullptr == alpn) && size) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        t_aho_corasick<byte_t> ac;
        std::multimap<unsigned, range_t> rearranged;

        ac.insert(&_prot[0], _prot.size());  // pattern [0]
        ac.build();

        auto result = ac.search(alpn, size);

        ac.order_by_pattern(result, rearranged);

        auto select = [&](unsigned patid) -> void {
            auto iter = rearranged.lower_bound(patid);
            if (rearranged.end() != iter) {
                auto ext = new tls_extension_alpn(session);
                ext->set_protocols(_prot);
                session->schedule_extension(ext);
                ext->release();
            }
        };

        select(0);

#if defined DEBUG
        if (istraceable()) {
            basic_stream dbs;
            dbs.println("> protocols");
            dump_memory(alpn, size, &dbs, 16, 3, 0, dump_notrunc);
            dbs.println("> pattern");
            dump_memory(_prot, &dbs, 16, 3, 0, dump_notrunc);
            trace_debug_event(trace_category_net, trace_event_tls_protection, &dbs);
        }
#endif
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
