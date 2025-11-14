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
#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/pattern/aho_corasick.hpp>
#include <hotplace/sdk/base/string/string.hpp>
#include <hotplace/sdk/base/unittest/trace.hpp>
#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/evp_pkey.hpp>
#include <hotplace/sdk/net/tls/quic/types.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_alpn.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake.hpp>
#include <hotplace/sdk/net/tls/tls/tls.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

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

    set_default_ciphersuites();
    set_default_tls_groups();
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
}

void tls_advisor::load_tls_extensiontype_values() {
    // valueof_compression_alg
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

    for (auto i = 0; i < sizeof_tls_secret_codes; i++) {
        auto item = tls_secret_codes + i;
        _secret_codes.insert({item->code, item});
    }

    for (auto i = 0; i < sizeof_tls_quic_stream_id_codes; i++) {
        auto item = tls_quic_stream_id_codes + i;
        _quic_stream_id_codes.insert({item->code, item});
    }

    for (auto i = 0; i < sizeof_tls_protection_space_codes; i++) {
        auto item = tls_protection_space_codes + i;
        _protection_space_codes.insert({item->code, item});
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

hash_algorithm_t tls_advisor::algof_hash(uint16 code) {
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

std::string tls_advisor::nameof_tls_version(uint16 code) {
    std::string value;
    auto iter = _tls_version.find(code);
    if (_tls_version.end() != iter) {
        auto item = iter->second;
        value = item->name;
    }
    return value;
}

std::string tls_advisor::nameof_compression_method(uint8 code) {
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

std::string tls_advisor::nameof_sni_nametype(uint16 code) {
    std::string value;
    if (0 == code) {
        value = "hostname";
    }
    return value;
}

std::string tls_advisor::nameof_quic_packet(uint8 code) {
    std::string value;
    auto iter = _quic_packet_type_codes.find(code);
    if (_quic_packet_type_codes.end() != iter) {
        auto item = iter->second;
        value = item->desc;
    }
    return value;
}

std::string tls_advisor::nameof_secret(tls_secret_t secret) {
    std::string value;
    auto iter = _secret_codes.find(secret);
    if (_secret_codes.end() != iter) {
        auto item = iter->second;
        value = item->desc;
    }
    return value;
}

std::string tls_advisor::nameof_quic_streamid_type(uint64 streamid) {
    std::string value;
    uint8 mask = streamid & 0x3;
    auto iter = _quic_stream_id_codes.find(mask);
    if (_quic_stream_id_codes.end() != iter) {
        auto item = iter->second;
        value = item->desc;
    }
    return value;
}

std::string tls_advisor::nameof_protection_space(protection_space_t code) {
    std::string value;
    auto iter = _protection_space_codes.find(code);
    if (_protection_space_codes.end() != iter) {
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

std::string tls_advisor::nameof_session_status(uint32 status) {
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

std::string tls_advisor::nameof_direction(tls_direction_t dir, uint32 flag) {
    std::string value;
    switch (dir) {
        case from_client: {
            if (0 == flag) {
                value = "client";
            } else if (1 == flag) {
                value = "client->server";
            } else {
                value = "client-initiated (uni-directional)";
            }
        } break;
        case from_server: {
            if (0 == flag) {
                value = "server";
            } else if (1 == flag) {
                value = "server->client";
            } else {
                value = "server-initiated (uni-directional)";
            }
        } break;
        case client_initiated_bidi: {
            if (0 == flag) {
                value = "client<->server";
            } else if (1 == flag) {
                value = "client<->server";
            } else {
                value = "client-initiated (bi-directional)";
            }
        } break;
        case server_initiated_bidi: {
            if (0 == flag) {
                value = "server<->client";
            } else if (1 == flag) {
                value = "server<->client";
            } else {
                value = "server-initiated (bi-directional)";
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

        ret_value = protection.get_key().find(kid, kty);
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

        ret_value = protection.get_key().find_x509(kid, kty);
        if (nullptr == ret_value) {
            ret_value = get_keys().find_x509(kid, kty);
        }
    }
    __finally2 {}
    return ret_value;
}

return_t tls_advisor::set_ciphersuites(const char* ciphersuites) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == ciphersuites) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        _ciphersuites.clear();

#if defined DEBUG
        if (istraceable(trace_category_net)) {
            trace_debug_event(trace_category_net, trace_event_tls_protection, [&](basic_stream& dbs) -> void { dbs.println("# set ciphersuite(s)"); });
        }
#endif

        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        auto lambda = [&](const std::string& item) -> void {
            auto hint = tlsadvisor->hintof_cipher_suite(item);
            if (hint && (tls_flag_support & hint->flags)) {
                auto code = hint->code;
                _ciphersuites.insert(code);
#if defined DEBUG
                if (istraceable(trace_category_net)) {
                    trace_debug_event(trace_category_net, trace_event_tls_protection,
                                      [&](basic_stream& dbs) -> void { dbs.println(" > 0x%02x %s", hint->code, hint->name_iana); });
                }
#endif
            }
        };

        split_context_t* context = nullptr;
        split_begin(&context, ciphersuites, ":");
        split_foreach(context, lambda);
        split_end(context);
    }
    __finally2 {}

    return ret;
}

return_t tls_advisor::set_default_ciphersuites() {
    return_t ret = errorcode_t::success;
    _ciphersuites.clear();
    return ret;
}

bool tls_advisor::test_ciphersuite(uint16 cs) {
    bool ret = false;
    if (_ciphersuites.empty()) {
        ret = true;
    } else {
        auto iter = _ciphersuites.find(cs);
        if (_ciphersuites.end() != iter) {
            ret = true;
        }
    }
    return ret;
}

return_t tls_advisor::set_tls_groups(const char* groups) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == groups) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        critical_section_guard guard(_lock);

        auto advisor = crypto_advisor::get_instance();
        auto lambda = [&](const std::string& item) -> void {
            auto hint = advisor->hintof_tls_group(item);
            if (hint && (tls_flag_support & hint->flags)) {
                auto code = hint->group;
                _groups.insert(code);
#if defined DEBUG
                if (istraceable(trace_category_net)) {
                    trace_debug_event(trace_category_net, trace_event_tls_protection,
                                      [&](basic_stream& dbs) -> void { dbs.println(" > 0x%02x %s", hint->group, hint->name); });
                }
#endif
            }
        };

        split_context_t* context = nullptr;
        split_begin(&context, groups, ":");
        split_foreach(context, lambda);
        split_end(context);
    }
    __finally2 {}
    return ret;
}

return_t tls_advisor::set_default_tls_groups() {
    return_t ret = errorcode_t::success;
    critical_section_guard guard(_lock);
    _groups.clear();
    _groups.insert(tls_group_x25519);
    _groups.insert(tls_group_secp256r1);
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    _groups.insert(tls_group_mlkem512);
    // _groups.insert(tls_group_mlkem768);
    // _groups.insert(tls_group_mlkem1024);
#endif
    return ret;
}

bool tls_advisor::test_tls_group(uint16 group) {
    bool ret = false;
    if (_groups.empty()) {
        ret = true;
    } else {
        critical_section_guard guard(_lock);
        auto iter = _groups.find(group);
        if (_groups.end() != iter) {
            ret = true;
        }
    }
    return ret;
}

void tls_advisor::for_each_tls_groups(std::function<void(uint16)> func) {
    if (func) {
        critical_section_guard guard(_lock);
        for (auto& group : _groups) {
            func(group);
        }
    }
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

return_t tls_advisor::negotiate_alpn(tls_handshake* handshake, const byte_t* alpn, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == handshake) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
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
                auto ext = new tls_extension_alpn(handshake);
                ext->set_protocols(_prot);
                handshake->get_session()->schedule_extension(ext);
                ext->release();
            }
        };

        select(0);

#if defined DEBUG
        if (istraceable(trace_category_net, loglevel_debug)) {
            trace_debug_event(trace_category_net, trace_event_tls_protection, [&](basic_stream& dbs) -> void {
                dbs.println("> protocols");
                dump_memory(alpn, size, &dbs, 16, 3, 0, dump_notrunc);
                dbs.println("> pattern");
                dump_memory(_prot, &dbs, 16, 3, 0, dump_notrunc);
            });
        }
#endif
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
