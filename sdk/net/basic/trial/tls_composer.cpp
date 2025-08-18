/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/nostd/exception.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/crypto/basic/openssl_prng.hpp>
#include <sdk/net/basic/trial/tls_composer.hpp>
#include <sdk/net/tls/dtls_record_publisher.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_ec_point_formats.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_key_share.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_psk_key_exchange_modes.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_renegotiation_info.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_signature_algorithms.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_supported_groups.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_supported_versions.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_unknown.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake_certificate.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake_certificate_verify.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake_client_hello.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake_client_key_exchange.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake_encrypted_extensions.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake_finished.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake_hello_verify_request.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake_server_hello.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake_server_hello_done.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake_server_key_exchange.hpp>
#include <sdk/net/tls/tls/record/tls_record.hpp>
#include <sdk/net/tls/tls/record/tls_record_application_data.hpp>
#include <sdk/net/tls/tls/record/tls_record_builder.hpp>
#include <sdk/net/tls/tls/record/tls_record_change_cipher_spec.hpp>
#include <sdk/net/tls/tls/record/tls_records.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_protection.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

tls_composer::tls_composer(tls_session* session) : _session(session), _minspec(tls_12), _maxspec(tls_13) {
    if (session) {
        session->addref();
    } else {
        throw exception(errorcode_t::no_session);
    }

    if (session_type_dtls == session->get_type()) {
        auto& publisher = session->get_dtls_record_publisher();
        publisher.set_fragment_size(1024);
        publisher.set_segment_size(1024);
        publisher.set_flags(dtls_record_publisher_multi_handshakes);
    }
}

tls_composer::~tls_composer() {
    auto session = get_session();
    if (session) {
        session->release();
    }
}

return_t tls_composer::handshake(tls_direction_t dir, unsigned wto, std::function<void(tls_session*, binary_t&)> func) {
    return_t ret = errorcode_t::success;
    if (from_client == dir) {
        ret = do_client_handshake(dir, wto, func);
    } else if (from_server == dir) {
        ret = errorcode_t::not_supported;
    }
    return ret;
}

return_t tls_composer::session_status_changed(uint32 session_status, tls_direction_t dir, uint32 wto, std::function<void(tls_session*, binary_t&)> func) {
    return_t ret = errorcode_t::success;
    tls_advisor* tlsadvisor = tls_advisor::get_instance();
    __try2 {
#if defined DEBUG
        if (istraceable(trace_category_net)) {
            basic_stream dbs;
            dbs.println("hook %s (%s)", tlsadvisor->session_status_string(session_status).c_str(), tlsadvisor->nameof_direction(dir).c_str());
            trace_debug_event(trace_category_net, trace_event_tls_handshake, &dbs);
        }
#endif
        if (from_client == dir) {
            ret = errorcode_t::not_supported;
        } else if (from_server == dir) {
            auto session = get_session();
            auto& protection = session->get_tls_protection();
            auto session_type = session->get_type();

            // TLS 1.3
            //   C client_hello
            //   S server_hello, certificate, certificate_verify, change_cipher_spec, finished
            //   C change_cipher_spec, finished
            // TLS 1.2
            //   C client_hello
            //   S server_hello, certificate, server_key_exchange, server_hello_done
            //   C client_key_exchange, change_cipher_spec, finished
            //   S change_cipher_spec, finished
            switch (session_status) {
                case session_status_client_hello: {
                    ret = do_server_handshake_phase1(func);
                } break;
                case session_status_client_finished: {
                    // TLS 1.2
                    if (protection.is_kindof_tls12()) {
                        ret = do_server_handshake_phase2(func);
                    }
                } break;
            }
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_composer::do_compose(tls_record* record, tls_direction_t dir, std::function<void(tls_session*, binary_t&)> func) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == record || nullptr == func) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto session = get_session();
        auto session_type = session->get_type();
        if (session_type_dtls == session_type) {
            // fragmentation
            session->get_dtls_record_publisher().publish(record, dir, func);
        } else {
            binary_t bin;
            ret = record->write(dir, bin);
            func(session, bin);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_composer::do_compose(tls_records* records, tls_direction_t dir, std::function<void(tls_session*, binary_t&)> func) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == records || nullptr == func) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto session = get_session();
        auto session_type = session->get_type();
        if (session_type_dtls == session_type) {
            // fragmentation
            session->get_dtls_record_publisher().publish(records, dir, func);
        } else {
            records->write(session, dir, func);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_composer::do_client_handshake(tls_direction_t dir, unsigned wto, std::function<void(tls_session*, binary_t&)> func) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        auto& protection = session->get_tls_protection();
        auto session_type = session->get_type();
        uint32 session_status = 0;

        uint8 retry = 3;
        do {
            ret = do_client_hello(func);
            if (errorcode_t::success != ret) {
                __leave2;
            }

            if (session_type_dtls == session_type) {
                session->wait_change_session_status(session_status_hello_verify_request, wto);
                session_status = session->get_session_status();

                if (0 == (session_status & session_status_hello_verify_request)) {
                    ret = errorcode_t::error_handshake;
                    __leave2_trace(ret);
                }

                // client_hello(cookie that server sent)
                ret = do_client_hello(func);
                if (errorcode_t::success != ret) {
                    __leave2;
                }
            }

            session->wait_change_session_status(session_status_server_hello, wto);
            session_status = session->get_session_status();

            if (0 == (session_status & session_status_server_hello)) {
                ret = errorcode_t::error_handshake;
                break;
            }
        } while ((tls_flow_hello_retry_request == protection.get_flow()) && (--retry));

        if (errorcode_t::success != ret) {
            __leave2;
        }
        if (tls_flow_1rtt != protection.get_flow()) {
            ret = errorcode_t::error_handshake;
            __leave2;
        }

        tls_records records;
        tls_record_builder builder;
        uint32 session_status_finished = 0;

        if (protection.is_kindof_tls13()) {
            uint32 session_status_prerequisite =
                session_status_server_hello | session_status_server_cert | session_status_server_cert_verified | session_status_server_finished;
            session->wait_change_session_status(session_status_prerequisite, wto);
            session_status = session->get_session_status();

            if (0 == (session_status & session_status_prerequisite)) {
                ret = error_handshake;
                __leave2_trace(ret);
            }

            {
                // change cipher spec
                records << builder.set(session).set(tls_content_type_change_cipher_spec).set(dir).construct().build();
            }

            {
                // client finished
                auto record = builder.set(session).set(tls_content_type_handshake).set(dir).construct().set_protected(true).build();
                *record << new tls_handshake_finished(session);
                records << record;

                session_status_finished = session_status_client_finished;
            }
        } else if (protection.is_kindof_tls12()) {
            // server_hello
            // certificate
            // server_key_exchange
            // server_hello_done
            uint32 session_status_prerequisite =
                session_status_server_hello | session_status_server_cert | session_status_server_key_exchange | session_status_server_hello_done;
            session->wait_change_session_status(session_status_prerequisite, wto);
            session_status = session->get_session_status();

            if (0 == (session_status & session_status_prerequisite)) {
                ret = errorcode_t::error_handshake;
                __leave2_trace(ret);
            }

            {
                // client_key_exchange
                auto record = builder.set(session).set(tls_content_type_handshake).set(dir).construct().build();
                *record << new tls_handshake_client_key_exchange(session);
                records << record;
            }
            {
                // change cipher spec
                records << builder.set(session).set(tls_content_type_change_cipher_spec).set(dir).construct().build();
            }
            {
                // client_finished
                auto record = builder.set(session).set(tls_content_type_handshake).set(dir).construct().set_protected(true).build();
                *record << new tls_handshake_finished(session);
                records << record;
            }

            session_status_finished = session_status_server_finished;
        }

        ret = do_compose(&records, dir, func);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        session->wait_change_session_status(session_status_finished, wto);
        session_status = session->get_session_status();

        if (0 == (session_status_finished & session_status)) {
            ret = errorcode_t::error_handshake;
            __leave2_trace(ret);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_composer::do_client_hello(std::function<void(tls_session*, binary_t&)> func) {
    return_t ret = errorcode_t::success;
    tls_advisor* tlsadvisor = tls_advisor::get_instance();
    tls_record* record = nullptr;
    tls_handshake* ch = nullptr;
    tls_direction_t dir = from_client;
    __try2 {
        if (nullptr == func) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto session = get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        uint32 session_status = 0;
        auto session_type = session->get_type();
        auto& protection = session->get_tls_protection();
        bool is_dtls = (session_type_dtls == session_type);

        tls_record_builder builder;
        record = builder.set(session).set(tls_content_type_handshake).set(dir).construct().build();
        if (nullptr == record) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        ret = construct_client_hello(&ch, session, nullptr, _minspec, _maxspec);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        (*record) << ch;

        do_compose(record, dir, func);
    }
    __finally2 {
        if (record) {
            record->release();
        }
    }
    return ret;
}

return_t tls_composer::do_server_handshake_phase1(std::function<void(tls_session*, binary_t&)> func) {
    return_t ret = errorcode_t::success;
    tls_record_builder builder;
    tls_advisor* tlsadvisor = tls_advisor::get_instance();
    tls_direction_t dir = from_server;
    tls_records records;
    __try2 {
        auto session = get_session();
        auto session_type = session->get_type();
        auto session_status = session->get_session_status();
        auto& protection = session->get_tls_protection();

        if ((session_type_dtls == session_type) && (0 == (session_status & session_status_hello_verify_request))) {
            // hello_verify_request cookie

            auto hs = new tls_handshake_hello_verify_request(session);
            hs->set_cookie(protection.get_secrets().get(tls_context_dtls_cookie));

            auto record = builder.set(session).set(tls_content_type_handshake).set(dir).construct().build();
            *record << hs;

            records << record;
        } else {
            // server_hello
            {
                tls_handshake* hs = nullptr;

                auto record = builder.set(session).set(tls_content_type_handshake).set(dir).construct().build();
                if (nullptr == record) {
                    ret = errorcode_t::not_supported;
                    __leave2;
                }

                ret = construct_server_hello(&hs, session, nullptr, _minspec, _maxspec);
                if (errorcode_t::success != ret) {
                    __leave2;
                }

                *record << hs;

                records << record;
            }
            auto tlsver = protection.get_protection_context().get0_supported_version();
            if (tlsadvisor->is_kindof_tls13(tlsver)) {
                {
                    // change_cipher_spec
                    records << builder.set(session).set(tls_content_type_change_cipher_spec).set(dir).construct().build();
                }
                {
                    // encrypted_extensions
                    auto record = builder.set(session).set(tls_content_type_handshake).set(dir).construct().set_protected(true).build();
                    *record << new tls_handshake_encrypted_extensions(session);
                    records << record;
                }
                {
                    // certificate
                    auto record = builder.set(session).set(tls_content_type_handshake).set(dir).construct().set_protected(true).build();
                    *record << new tls_handshake_certificate(session);
                    records << record;
                }
                {
                    // certificate_verify
                    auto record = builder.set(session).set(tls_content_type_handshake).set(dir).construct().set_protected(true).build();
                    *record << new tls_handshake_certificate_verify(session);
                    records << record;
                }
                {
                    // finished
                    auto record = builder.set(session).set(tls_content_type_handshake).set(dir).construct().set_protected(true).build();
                    *record << new tls_handshake_finished(session);
                    records << record;
                }
            } else {
                {
                    // certificate
                    auto record = builder.set(session).set(tls_content_type_handshake).set(dir).construct().build();
                    *record << new tls_handshake_certificate(session);

                    records << record;
                }
                {
                    // server_key_exchange
                    auto record = builder.set(session).set(tls_content_type_handshake).set(dir).construct().build();
                    *record << new tls_handshake_server_key_exchange(session);
                    records << record;
                }
                {
                    // server_hello_done
                    auto record = builder.set(session).set(tls_content_type_handshake).set(dir).construct().build();
                    *record << new tls_handshake_server_hello_done(session);
                    records << record;
                }
            }
        }

        do_compose(&records, dir, func);
    }
    __finally2 {}
    return ret;
}

return_t tls_composer::do_server_handshake_phase2(std::function<void(tls_session*, binary_t&)> func) {
    return_t ret = errorcode_t::success;
    tls_record_builder builder;
    tls_advisor* tlsadvisor = tls_advisor::get_instance();
    tls_direction_t dir = from_server;
    tls_records records;
    __try2 {
        auto session = get_session();

        {
            // change_cipher_spec
            records << builder.set(session).set(tls_content_type_change_cipher_spec).set(dir).construct().build();
        }
        {
            // finished
            auto record = builder.set(session).set(tls_content_type_handshake).set(dir).construct().set_protected(true).build();
            *record << new tls_handshake_finished(session);
            records << record;
        }

        do_compose(&records, dir, func);
    }
    __finally2 {}
    return ret;
}

tls_session* tls_composer::get_session() { return _session; }

void tls_composer::set_minver(tls_version_t version) {
    tls_advisor* tlsadvisor = tls_advisor::get_instance();
    auto hint = tlsadvisor->hintof_tls_version(version);
    if (hint) {
        _minspec = hint->spec;
    }
}

void tls_composer::set_maxver(tls_version_t version) {
    tls_advisor* tlsadvisor = tls_advisor::get_instance();
    auto hint = tlsadvisor->hintof_tls_version(version);
    if (hint) {
        _maxspec = hint->spec;
    }
}

uint16 tls_composer::get_minver() { return _minspec; }

uint16 tls_composer::get_maxver() { return _maxspec; }

return_t tls_composer::construct_client_hello(tls_handshake** handshake, tls_session* session, std::function<return_t(tls_handshake*, tls_direction_t)> hook,
                                              uint16 minspec, uint16 maxspec) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == handshake || nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        uint32 session_status = 0;
        auto session_type = session->get_type();
        auto& protection = session->get_tls_protection();
        bool is_dtls = (session_type_dtls == session_type);
        tls_handshake_client_hello* hs = nullptr;

        __try_new_catch(hs, new tls_handshake_client_hello(session), ret, __leave2);

        // random
        {
            openssl_prng prng;

            binary_t random;  // gmt_unix_time(4 bytes) + random(28 bytes)
            time_t gmt_unix_time = time(nullptr);
            binary_append(random, gmt_unix_time, hton32);
            random.resize(sizeof(uint32));
            binary_t temp;
            prng.random(temp, 28);
            binary_append(random, temp);
            hs->set_random(random);
        }

        // cookie
        {
            session_status = session->get_session_status();
            if (session_status_hello_verify_request & session_status) {
                const auto& cookie = protection.get_secrets().get(tls_context_cookie);
                if (false == cookie.empty()) {
                    hs->set_cookie(cookie);
                }
            }
        }

        {
            // cipher suites
            uint8 mask = tls_flag_secure | tls_flag_support;
            auto lambda_cs = [&](const tls_cipher_suite_t* cs) -> void {
                if ((mask & cs->flags) && (cs->version >= minspec) && (cs->version <= maxspec)) {
                    hs->add_ciphersuite(cs->code);
                }
            };
            tlsadvisor->enum_cipher_suites(lambda_cs);
        }

        {
            // encrypt_then_mac
            if (tls_12 == minspec) {
                if (session->get_keyvalue().get(session_conf_enable_encrypt_then_mac)) {
                    hs->get_extensions().add(new tls_extension_unknown(tls_ext_encrypt_then_mac, hs));
                }
            }
        }

        {
            // ec_point_formats
            // RFC 9325 4.2.1
            // Note that [RFC8422] deprecates all but the uncompressed point format.
            // Therefore, if the client sends an ec_point_formats extension, the ECPointFormatList MUST contain a single element, "uncompressed".
            auto ec_point_formats = new tls_extension_ec_point_formats(hs);
            (*ec_point_formats).add("uncompressed");
            hs->get_extensions().add(ec_point_formats);
        }
        {
            // supported_groups
            // Clients and servers SHOULD support the NIST P-256 (secp256r1) [RFC8422] and X25519 (x25519) [RFC7748] curves
            auto supported_groups = new tls_extension_supported_groups(hs);
            (*supported_groups).add("x25519").add("secp256r1").add("x448").add("secp521r1").add("secp384r1");
            hs->get_extensions().add(supported_groups);
        }
        {
            // signature_algorithms
            auto signature_algorithms = new tls_extension_signature_algorithms(hs);
            (*signature_algorithms)
                .add("ecdsa_secp256r1_sha256")
                .add("ecdsa_secp384r1_sha384")
                .add("ecdsa_secp521r1_sha512")
                .add("ed25519")
                .add("ed448")
                .add("rsa_pkcs1_sha256")
                .add("rsa_pkcs1_sha384")
                .add("rsa_pkcs1_sha512")
                .add("rsa_pss_pss_sha256")
                .add("rsa_pss_pss_sha384")
                .add("rsa_pss_pss_sha512")
                .add("rsa_pss_rsae_sha256")
                .add("rsa_pss_rsae_sha384")
                .add("rsa_pss_rsae_sha512");
            hs->get_extensions().add(signature_algorithms);
        }

        if (tls_13 == maxspec) {
            // TLS 1.3
            {
                // supported_versions
                auto supported_versions = new tls_extension_client_supported_versions(hs);
                if (tls_13 == maxspec) {
                    (*supported_versions).add(is_dtls ? dtls_13 : tls_13);
                }
                if (tls_12 == minspec) {
                    (*supported_versions).add(is_dtls ? dtls_12 : tls_12);
                }
                hs->get_extensions().add(supported_versions);
            }
            {
                // psk_key_exchange_modes
                auto psk_key_exchange_modes = new tls_extension_psk_key_exchange_modes(hs);
                (*psk_key_exchange_modes).add("psk_dhe_ke");
                hs->get_extensions().add(psk_key_exchange_modes);
            }
            {
                // key_share
                auto key_share = new tls_extension_client_key_share(hs);
                if (tls_flow_hello_retry_request != protection.get_flow()) {
                    (*key_share).add("x25519");
                }
                hs->get_extensions().add(key_share);
            }
        }

        {
            // session_ticket
            hs->get_extensions().add(new tls_extension_unknown(tls_ext_session_ticket, hs));
            // renegotiation_info
            hs->get_extensions().add(new tls_extension_renegotiation_info(hs));
            // master_secret
            hs->get_extensions().add(new tls_extension_unknown(tls_ext_extended_master_secret, hs));
        }

        if (hook) {
            hook(hs, from_client);
        }

        *handshake = hs;
    }
    __finally2 {}
    return ret;
}

return_t tls_composer::construct_server_hello(tls_handshake** handshake, tls_session* session, std::function<return_t(tls_handshake*, tls_direction_t)> hook,
                                              uint16 minspec, uint16 maxspec) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == handshake || nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        uint16 cs = 0;
        uint16 tlsver = 0;
        auto& protection = session->get_tls_protection();
        ret = protection.negotiate(session, cs, tlsver);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        tls_handshake_server_hello* hs = nullptr;

        __try_new_catch(hs, new tls_handshake_server_hello(session), ret, __leave2);

        hs->set_cipher_suite(cs);

        if (tlsadvisor->is_kindof_tls13(tlsver)) {
            {
                auto supported_versions = new tls_extension_server_supported_versions(hs);
                (*supported_versions).set(tlsver);
                hs->get_extensions().add(supported_versions);
            }

            {
                auto key_share = new tls_extension_server_key_share(hs);
                key_share->clear();
                key_share->add_keyshare();
                hs->get_extensions().add(key_share);
            }
        } else {
            {
                auto renegotiation_info = new tls_extension_renegotiation_info(hs);
                hs->get_extensions().add(renegotiation_info);
            }
            {
                auto ec_point_formats = new tls_extension_ec_point_formats(hs);
                (*ec_point_formats).add("uncompressed");
                hs->get_extensions().add(ec_point_formats);
            }
            {
                auto supported_groups = new tls_extension_supported_groups(hs);
                (*supported_groups).add("x25519");
                hs->get_extensions().add(supported_groups);
            }
            {
                // hs->get_extensions().add(new tls_extension_unknown(tls_ext_encrypt_then_mac, hs));
                // hs->get_extensions().add(new tls_extension_unknown(tls_ext_extended_master_secret, hs));
            }
        }

        if (hook) {
            hook(hs, from_server);
        }

        *handshake = hs;
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
