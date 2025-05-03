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
#include <sdk/net/basic/tls/dtls_client_socket2.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_ec_point_formats.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_key_share.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_psk_key_exchange_modes.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_renegotiation_info.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_signature_algorithms.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_sni.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_supported_groups.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_supported_versions.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_unknown.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake_client_hello.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake_client_key_exchange.hpp>
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

dtls_client_socket2::dtls_client_socket2(tls_version_t minver) : async_client_socket(), _minver(minver) {
    auto session = &_session;
    session->set_type(session_dtls);
}

return_t dtls_client_socket2::sendto(const char* ptr_data, size_t size_data, size_t* cbsent, const struct sockaddr* addr, socklen_t addrlen) {
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

return_t dtls_client_socket2::do_handshake() {
    return_t ret = errorcode_t::success;
    const size_t bufsize = (1 << 16);
    char buffer[bufsize];

    __try2 {
        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        size_t cbsent = 0;
        binary_t bin;
        uint32 session_status = 0;

        auto session = &_session;
        auto& protection = session->get_tls_protection();
        tls_direction_t dir = from_client;

        // client hello
        {
            tls_record_builder builder;
            auto record = builder.set(session).set(tls_content_type_handshake).set(dir).construct().build();
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

            bool enable_etm = false;
            if (session->get_keyvalue().get(session_enable_encrypt_then_mac)) {
                enable_etm = true;
            }

            // cipher suites
            {
                auto lambda_cs = [&](const tls_cipher_suite_t* cs) -> void {
                    if (cs->version >= _minver) {
                        if (enable_etm && (dtls_12 == _minver)) {
                            if (cbc == cs->mode) {
                                handshake->add_ciphersuite(cs->code);
                            }
                        } else {
                            handshake->add_ciphersuite(cs->code);
                        }
                    }
                };
                tlsadvisor->enum_cipher_suites(lambda_cs);
            }
            {
                handshake->get_extensions().add(new tls_extension_renegotiation_info(session));
                handshake->get_extensions().add(new tls_extension_unknown(tls_ext_session_ticket, session));
                if (enable_etm && (dtls_12 == _minver)) {
                    handshake->get_extensions().add(new tls_extension_unknown(tls_ext_encrypt_then_mac, session));
                }
                // handshake->get_extensions().add(new tls_extension_unknown(tls_ext_extended_master_secret, session));
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
                if (_minver == dtls_13) {
                    (*supported_versions).add(dtls_13);
                }
                (*supported_versions).add(dtls_12);
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

            *record << handshake;
            ret = record->write(dir, bin);
            record->release();
        }  // end of client hello

        if (errorcode_t::success != ret) {
            __leave2;
        }

        uint32 server_session_status =
            session_status_server_hello | session_status_server_cert | session_status_server_key_exchange | session_status_server_hello_done;
        session->wait_change_session_status(server_session_status, get_wto());
        session_status = session->get_session_status();

        if (0 == (session_status & server_session_status)) {
            ret = error_handshake;
            __leave2;
        }

        // client_key_exchange
        {
            tls_record_builder builder;
            auto record = builder.set(session).set(tls_content_type_handshake).set(dir).construct().build();
            *record << new tls_handshake_client_key_exchange(session);
            record->write(dir, bin);
            record->release();
        }
        // change_cipher_spec
        {
            tls_record_change_cipher_spec record(session);
            record.write(dir, bin);
        }
        // client finished
        {
            tls_record_builder builder;
            auto record = builder.set(session).set(tls_content_type_handshake).set(dir).construct().build();
            *record << new tls_handshake_finished(session);
            record->write(dir, bin);
            record->release();
        }

        ret = async_client_socket::sendto((char*)&bin[0], bin.size(), &cbsent, (sockaddr*)&_sa, sizeof(_sa));
        bin.clear();
    }
    __finally2 {}

    return ret;
}

return_t dtls_client_socket2::do_read(char* ptr_data, size_t size_data, size_t* cbread, struct sockaddr* addr, socklen_t* addrlen) {
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

return_t dtls_client_socket2::do_secure() {
    return_t ret = errorcode_t::success;
    auto type = socket_type();
    tls_direction_t dir = from_server;

    {
        critical_section_guard guard(_rlock);

        while (false == _rq.empty()) {
            const auto& item = _rq.front();
            _mbs << item.buffer;
            _rq.pop();
        }

        const byte_t* stream = _mbs.data();
        size_t size = _mbs.size();
        size_t pos = 0;
        while (pos < size) {
            uint8 content_type = stream[pos];
            tls_record_builder builder;
            auto record = builder.set(&_session).set(content_type).build();
            if (record) {
                ret = record->read(dir, stream, size, pos);
                if (errorcode_t::success == ret) {
                    if (tls_content_type_application_data == content_type) {
                        tls_record_application_data* appdata = (tls_record_application_data*)record;
                        const auto& bin = appdata->get_binary();

                        if (false == bin.empty()) {
                            bufferqueue_item_t item;
                            item.buffer << bin;

                            critical_section_guard guard(_mlock);
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
    // {
    //     binary_t bin;
    //
    //     auto lambda = [&](uint8 level, uint8 desc) -> void {
    //         tls_record_application_data record(session);
    //         record.get_records().add(new tls_record_alert(session, level, desc));
    //         record.write(dir, bin);
    //     };
    //     session->get_alert(dir, lambda);
    //
    //     if (false == bin.empty()) {
    //         size_t cbsent = 0;
    //         ret = async_client_socket::send((char*)&bin[0], bin.size(), &cbsent);
    //     }
    // }

    return ret;
}

return_t dtls_client_socket2::do_shutdown() {
    return_t ret = errorcode_t::success;
    __try2 {}
    __finally2 {}
    return ret;
}

bool dtls_client_socket2::support_tls() { return true; }

int dtls_client_socket2::socket_type() { return SOCK_DGRAM; }

}  // namespace net
}  // namespace hotplace
