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
#include <sdk/crypto/basic/openssl_prng.hpp>
#include <sdk/net/basic/tls/tls_composer.hpp>
#include <sdk/net/tls/dtls_record_publisher.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_ec_point_formats.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_key_share.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_psk_key_exchange_modes.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_renegotiation_info.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_signature_algorithms.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_supported_groups.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_supported_versions.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_unknown.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake_client_hello.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake_client_key_exchange.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake_finished.hpp>
#include <sdk/net/tls/tls/record/tls_record.hpp>
#include <sdk/net/tls/tls/record/tls_record_builder.hpp>
#include <sdk/net/tls/tls/record/tls_record_change_cipher_spec.hpp>
#include <sdk/net/tls/tls/record/tls_records.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

tls_composer::tls_composer(tls_session* session) : _session(session), _minver(tls_12), _maxver(tls_13) {
    if (session) {
        session->addref();
    } else {
        throw exception(no_session);
    }
}

tls_composer::~tls_composer() {
    auto session = get_session();
    if (session) {
        session->release();
    }
}

return_t tls_composer::handshake(tls_direction_t dir, unsigned wto, std::function<void(binary_t&)> func) {
    return_t ret = errorcode_t::success;
    if (from_client == dir) {
        ret = do_client_handshake(dir, wto, func);
    } else if (from_server == dir) {
        ret = do_server_handshake(dir, wto, func);
    }
    return ret;
}

return_t tls_composer::do_compose(tls_record* record, tls_direction_t dir, std::function<void(binary_t&)> func) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == record || nullptr == func) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto session = get_session();
        auto session_type = session->get_type();
        if (session_dtls == session_type) {
            // fragmentation
            session->get_dtls_record_publisher().publish(record, dir, func);
        } else {
            binary_t bin;
            ret = record->write(dir, bin);
            func(bin);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_composer::do_compose(tls_records* records, tls_direction_t dir, std::function<void(binary_t&)> func) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == records || nullptr == func) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto session = get_session();
        auto session_type = session->get_type();
        if (session_dtls == session_type) {
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

return_t tls_composer::do_client_handshake(tls_direction_t dir, unsigned wto, std::function<void(binary_t&)> func) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        auto& protection = session->get_tls_protection();
        uint32 session_status = 0;

        ret = do_client_hello(func);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        session->wait_change_session_status(session_status_server_hello, wto);
        session_status = session->get_session_status();

        if (0 == (session_status & session_status_server_hello)) {
            ret = errorcode_t::error_handshake;
            __leave2;
        }

        auto tlsver = protection.get_tls_version();

        tls_records records;
        tls_record_builder builder;

        if (tls_13 == tlsver) {
            uint32 session_status_prerequisite =
                session_status_server_hello | session_status_server_cert | session_status_server_cert_verified | session_status_server_finished;
            session->wait_change_session_status(session_status_prerequisite, wto);
            session_status = session->get_session_status();

            if (0 == (session_status & session_status_prerequisite)) {
                ret = error_handshake;
                __leave2;
            }

            // change cipher spec
            records << new tls_record_change_cipher_spec(session);

            session->get_session_info(dir).begin_protection();

            // client finished
            auto record = builder.set(session).set(tls_content_type_handshake).set(dir).construct().build();
            *record << new tls_handshake_finished(session);
            records << record;
        } else if (tls_12 == tlsver) {
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
                __leave2;
            }

            {
                // client_key_exchange
                auto record = builder.set(session).set(tls_content_type_handshake).set(dir).construct().build();
                *record << new tls_handshake_client_key_exchange(session);
                records << record;
            }
            {
                // change cipher spec
                records << new tls_record_change_cipher_spec(session);
            }
            {
                // client_finished
                auto record = builder.set(session).set(tls_content_type_handshake).set(dir).construct().build();
                *record << new tls_handshake_finished(session);
                records << record;
            }
        }

        ret = do_compose(&records, dir, func);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        session->wait_change_session_status(session_status_server_finished, wto);
        session_status = session->get_session_status();

        if (0 == (session_status & session_status_server_finished)) {
            ret = errorcode_t::error_handshake;
            __leave2;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_composer::do_server_handshake(tls_direction_t dir, unsigned wto, std::function<void(binary_t&)> func) {
    // TODO ... server socket
    return_t ret = errorcode_t::not_implemented;
    return ret;
}

return_t tls_composer::do_client_hello(std::function<void(binary_t&)> func) {
    return_t ret = errorcode_t::success;
    tls_record* record = nullptr;
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

        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        auto session_status = session->get_session_status();
        auto session_type = session->get_type();
        auto& protection = session->get_tls_protection();
        auto dir = from_client;

        tls_record_builder builder;
        record = builder.set(session).set(tls_content_type_handshake).set(dir).construct().build();
        if (nullptr == record) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        tls_handshake_client_hello* handshake = nullptr;
        __try_new_catch(handshake, new tls_handshake_client_hello(session), ret, __leave2);

        // random
        {
            openssl_prng prng;

            binary_t random;  // gmt_unix_time(4 bytes) + random(28 bytes)
            time_t gmt_unix_time = time(nullptr);
            binary_append(random, gmt_unix_time, hton64);
            random.resize(sizeof(uint32));
            binary_t temp;
            prng.random(temp, 28);
            binary_append(random, temp);
            handshake->set_random(random);
        }

        {
            // cipher suites
            uint8 mask = tls_cs_secure | tls_cs_support;
            auto lambda_cs = [&](const tls_cipher_suite_t* cs) -> void {
                if ((mask & cs->flags) && (cs->version >= _minver)) {
                    handshake->add_ciphersuite(cs->code);
                }
            };
            tlsadvisor->enum_cipher_suites(lambda_cs);
        }

        {
            // encrypt_then_mac
            if (tls_12 == _minver) {
                if (session->get_keyvalue().get(session_enable_encrypt_then_mac)) {
                    handshake->get_extensions().add(new tls_extension_unknown(tls_ext_encrypt_then_mac, session));
                }
            }
        }
        {
            // ec_point_formats
            // RFC 9325 4.2.1
            // Note that [RFC8422] deprecates all but the uncompressed point format.
            // Therefore, if the client sends an ec_point_formats extension, the ECPointFormatList MUST contain a single element, "uncompressed".
            auto ec_point_formats = new tls_extension_ec_point_formats(session);
            (*ec_point_formats).add("uncompressed");
            handshake->get_extensions().add(ec_point_formats);
        }
        {
            // supported_groups
            // Clients and servers SHOULD support the NIST P-256 (secp256r1) [RFC8422] and X25519 (x25519) [RFC7748] curves
            auto supported_groups = new tls_extension_supported_groups(session);
            (*supported_groups).add("x25519").add("secp256r1").add("x448").add("secp521r1").add("secp384r1");
            handshake->get_extensions().add(supported_groups);
        }
        {
            // signature_algorithms
            auto signature_algorithms = new tls_extension_signature_algorithms(session);
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
            handshake->get_extensions().add(signature_algorithms);
        }

        if (tls_13 == _maxver) {
            // TLS 1.3
            {
                // supported_versions
                auto supported_versions = new tls_extension_client_supported_versions(session);
                (*supported_versions).add(tls_13);
                if (tls_12 == _minver) {
                    (*supported_versions).add(tls_12);
                }
                handshake->get_extensions().add(supported_versions);
            }
            {
                // psk_key_exchange_modes
                auto psk_key_exchange_modes = new tls_extension_psk_key_exchange_modes(session);
                (*psk_key_exchange_modes).add("psk_dhe_ke");
                handshake->get_extensions().add(psk_key_exchange_modes);
            }
            {
                // key_share
                auto key_share = new tls_extension_client_key_share(session);
                (*key_share).add("x25519");
                handshake->get_extensions().add(key_share);
            }
        }

        {
            // session_ticket
            handshake->get_extensions().add(new tls_extension_unknown(tls_ext_session_ticket, session));
        }
        {
            // renegotiation_info
            handshake->get_extensions().add(new tls_extension_renegotiation_info(session));
        }
        {
            // master_secret
            // handshake->get_extensions().add(new tls_extension_unknown(tls_ext_extended_master_secret, session));
        }

        {
            (*record) << handshake;

            do_compose(record, dir, func);
        }
    }
    __finally2 {
        if (record) {
            record->release();
        }
    }
    return ret;
}

return_t tls_composer::do_server_hello(std::function<void(binary_t&)> func) {
    // TODO ... server socket
    return_t ret = errorcode_t::not_implemented;
    return ret;
}

tls_session* tls_composer::get_session() { return _session; }

void tls_composer::set_minver(tls_version_t version) { _minver = version; }

void tls_composer::set_maxver(tls_version_t version) { _maxver = version; }

tls_version_t tls_composer::get_minver() { return _minver; }

tls_version_t tls_composer::get_maxver() { return _maxver; }

}  // namespace net
}  // namespace hotplace
