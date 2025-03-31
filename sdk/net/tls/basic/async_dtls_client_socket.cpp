/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *          openssl not support DTLS 1.3 yet
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/crypto/basic/openssl_prng.hpp>
#include <sdk/net/tls/basic/async_dtls_client_socket.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_ec_point_formats.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_key_share.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_psk_key_exchange_modes.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_signature_algorithms.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_sni.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_supported_groups.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_supported_versions.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_unknown.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake_client_hello.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake_finished.hpp>
#include <sdk/net/tls/tls/record/dtls13_ciphertext.hpp>
#include <sdk/net/tls/tls/record/tls_record_ack.hpp>
#include <sdk/net/tls/tls/record/tls_record_alert.hpp>
#include <sdk/net/tls/tls/record/tls_record_application_data.hpp>
#include <sdk/net/tls/tls/record/tls_record_builder.hpp>
#include <sdk/net/tls/tls/record/tls_record_change_cipher_spec.hpp>
#include <sdk/net/tls/tls/record/tls_record_handshake.hpp>
#include <sdk/net/tls/tls/tls.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/types.hpp>

namespace hotplace {
namespace net {

async_dtls_client_socket::async_dtls_client_socket(tls_version_t minver) : async_client_socket(), _minver(minver) {
    auto session = &_session;
    session->get_tls_protection().set_legacy_version(dtls_12);
}

return_t async_dtls_client_socket::sendto(const char* ptr_data, size_t size_data, size_t* cbsent, const struct sockaddr* addr, socklen_t addrlen) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == ptr_data || nullptr == cbsent || nullptr == addr) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        *cbsent = 0;

        auto session = &_session;
        binary_t bin;

        auto tlsver = session->get_tls_protection().get_tls_version();

        if (dtls_13 == tlsver) {
            dtls13_ciphertext record(tls_content_type_application_data, session);
            record.get_records().add(new tls_record_application_data(session, (byte_t*)ptr_data, size_data));
            record.write(from_client, bin);
        } else {
            tls_record_application_data record(session);
            record.get_records().add(new tls_record_application_data(session, (byte_t*)ptr_data, size_data));
            record.write(from_client, bin);
        }

        size_t sent = 0;
        ret = async_client_socket::sendto((char*)&bin[0], bin.size(), &sent, addr, addrlen);
        if (errorcode_t::success == ret) {
            *cbsent = size_data;
        }
    }
    __finally2 {}
    return ret;
}

return_t async_dtls_client_socket::do_handshake() {
    return_t ret = errorcode_t::success;
    const size_t bufsize = (1 << 16);
    char buffer[bufsize];

    __try2 {
        size_t cbsent = 0;
        binary_t bin;
        uint16 session_status = 0;

        auto session = &_session;
        auto& protection = session->get_tls_protection();

        // client hello
        tls_record_handshake clienthello(session);
        {
            tls_handshake_client_hello* handshake = nullptr;

            handshake = new tls_handshake_client_hello(session);

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

            // cipher suites
            {
                handshake->add_ciphersuite(0x1301);
                handshake->add_ciphersuite(0x1302);
                handshake->add_ciphersuite(0x1303);
                handshake->add_ciphersuite(0x1304);
                handshake->add_ciphersuite(0x1305);
            }
            {
                // RFC 9325 4.2.1
                // Note that [RFC8422] deprecates all but the uncompressed point format.
                // Therefore, if the client sends an ec_point_formats extension, the ECPointFormatList MUST contain a single element, "uncompressed".
                auto ec_point_formats = new tls_extension_ec_point_formats(session);
                (*ec_point_formats).add("uncompressed");
                handshake->get_extensions().add(ec_point_formats);
            }
            {
                // Clients and servers SHOULD support the NIST P-256 (secp256r1) [RFC8422] and X25519 (x25519) [RFC7748] curves
                auto supported_groups = new tls_extension_supported_groups(session);
                (*supported_groups).add("x25519").add("secp256r1").add("x448").add("secp521r1").add("secp384r1");
                handshake->get_extensions().add(supported_groups);
            }
            {
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
            {
                auto supported_versions = new tls_extension_client_supported_versions(session);
                (*supported_versions).add(dtls_13);
                if (_minver < tls_13) {
                    (*supported_versions).add(dtls_12);
                }
                handshake->get_extensions().add(supported_versions);
            }
            {
                auto psk_key_exchange_modes = new tls_extension_psk_key_exchange_modes(session);
                (*psk_key_exchange_modes).add("psk_dhe_ke");
                handshake->get_extensions().add(psk_key_exchange_modes);
            }
            {
                auto key_share = new tls_extension_client_key_share(session);
                (*key_share).add("x25519");
                handshake->get_extensions().add(key_share);
            }

            clienthello.get_handshakes().add(handshake);
            ret = clienthello.write(from_client, bin);
        }  // end of client hello

        ret = async_client_socket::sendto((char*)&bin[0], bin.size(), &cbsent, (sockaddr*)&_sa, sizeof(_sa));

        // DTLS 1.2 server key exchange
        session->wait1_change_session_status(session_hello_verify_request | session_server_key_exchange | session_server_finished,
                                             1000);  // wait server hello .. server finished
        session_status = session->get_session_status();

        if (session_status & session_hello_verify_request) {
            const binary_t& cookie = protection.get_item(tls_context_cookie);
            tls_handshake_client_hello* handshake = (tls_handshake_client_hello*)clienthello.get_handshakes().get(tls_hs_client_hello);
            handshake->set_cookie(cookie);
            ret = clienthello.write(from_client, bin);
            ret = async_client_socket::sendto((char*)&bin[0], bin.size(), &cbsent, (sockaddr*)&_sa, sizeof(_sa));

            session->wait1_change_session_status(session_server_cert_verified | session_server_finished, 1000);  // wait server hello .. server finished
            session_status = session->get_session_status();
        }

#if defined DEBUG
        if (istraceable()) {
            basic_stream dbs;
            dbs.println("> session status 0x%04x", session_status);
            trace_debug_event(category_debug_internal, 0, &dbs);
        }
#endif

        if (0 == (session_status & (session_server_cert_verified | session_server_finished))) {
            ret = error_handshake;
            __leave2;
        }

        auto tlsver = session->get_tls_protection().get_tls_version();

        bin.clear();

        // client finished
        {
            tls_record_application_data record(session);
            record.get_handshakes().add(new tls_handshake_finished(session));
            record.write(from_client, bin);
        }

        // client ack
        if (dtls_13 == tlsver) {
            dtls13_ciphertext record(tls_content_type_ack, session);
            record.get_records().add(new tls_record_ack(session));
            record.write(from_client, bin);
        } else {
            tls_record_ack record(session);
            record.write(from_client, bin);
        }

        ret = async_client_socket::sendto((char*)&bin[0], bin.size(), &cbsent, (sockaddr*)&_sa, sizeof(_sa));
    }
    __finally2 {}

    return ret;
}

return_t async_dtls_client_socket::do_read(char* ptr_data, size_t size_data, size_t* cbread, struct sockaddr* addr, socklen_t* addrlen) {
    return_t ret = errorcode_t::success;
    *cbread = 0;
    auto type = socket_type();
    auto test = _msem.wait(get_wto());
    if (errorcode_t::success == test) {
        critical_section_guard guard(_mlock);
        if (false == _mq.empty()) {
            auto& item = _mq.front();

            if (SOCK_DGRAM == type) {
                memcpy(addr, &item.addr, sizeof(sockaddr_storage_t));
            }

            auto datasize = item.buffer.size();
            if (datasize >= size_data) {
                memcpy(ptr_data, item.buffer.data(), size_data);
                item.buffer.cut(0, size_data);

                *cbread = size_data;

                if (false == support_tls()) {
                    _rsem.signal();
                }
            } else {
                memcpy(ptr_data, item.buffer.data(), datasize);

                *cbread = datasize;

                _mq.pop();
            }
            if (false == _mq.empty()) {
                ret = more_data;
            }
        }
    }

    return ret;
}

return_t async_dtls_client_socket::do_secure() {
    return_t ret = errorcode_t::success;
    auto session = &_session;
    auto type = socket_type();
    tls_direction_t dir = from_server;

    if (SOCK_STREAM == type) {
        {
            critical_section_guard guard(_rlock);
            while (false == _rq.empty()) {
                const auto& item = _rq.front();
                _mbs << item.buffer;
                _rq.pop();
            }
        }
        {
            byte_t* stream = _mbs.data();
            size_t size = _mbs.size();
            size_t pos = 0;
            while (pos < size) {
                uint8 content_type = stream[pos];
                tls_record_builder builder;
                auto record = builder.set(session).set(content_type).build();
                if (record) {
                    ret = record->read(dir, stream, size, pos);
                    if (errorcode_t::success == ret) {
                        if (tls_content_type_application_data == content_type) {
                            tls_record_application_data* appdata = (tls_record_application_data*)record;
                            const auto& bin = appdata->get_binary();

                            if (false == bin.empty()) {
                                bufferqueue_item_t item;
                                critical_section_guard guard(_mlock);
                                item.buffer << bin;
                                _mq.push(std::move(item));

                                _msem.signal();
                            }
                        }
                    }
                    record->release();
                }
            }
            _mbs.cut(0, pos);
        }
        // RFC 2246 7.2.2. Error alerts
        // RFC 8448 6.2.  Error Alerts
        {
            binary_t bin;

            auto lambda = [&](uint8 level, uint8 desc) -> void {
                tls_record_application_data record(session);
                record.get_records().add(new tls_record_alert(session, level, desc));
                record.write(dir, bin);
            };
            session->get_alert(dir, lambda);

            if (false == bin.empty()) {
                size_t cbsent = 0;
                ret = async_client_socket::send((char*)&bin[0], bin.size(), &cbsent);
            }
        }
    }
    return ret;
}

return_t async_dtls_client_socket::do_shutdown() {
    return_t ret = errorcode_t::success;
    __try2 {}
    __finally2 {}
    return ret;
}

bool async_dtls_client_socket::support_tls() { return true; }

int async_dtls_client_socket::socket_type() { return SOCK_DGRAM; }

}  // namespace net
}  // namespace hotplace
