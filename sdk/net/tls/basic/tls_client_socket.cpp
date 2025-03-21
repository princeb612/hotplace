/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto/basic/openssl_prng.hpp>
#include <sdk/net/tls/basic/tls_client_socket.hpp>
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
#include <sdk/net/tls/tls/record/tls_record_alert.hpp>
#include <sdk/net/tls/tls/record/tls_record_application_data.hpp>
#include <sdk/net/tls/tls/record/tls_record_builder.hpp>
#include <sdk/net/tls/tls/record/tls_record_change_cipher_spec.hpp>
#include <sdk/net/tls/tls/record/tls_record_handshake.hpp>
#include <sdk/net/tls/tls/tls.hpp>
#include <sdk/net/tls/tls_advisor.hpp>

namespace hotplace {
namespace net {

tls_client_socket2::tls_client_socket2(tls_version_t minver) : tcp_client_socket(), _minver(minver) {}

return_t tls_client_socket2::connect(const char* address, uint16 port, uint32 timeout) {
    return_t ret = errorcode_t::success;
    __try2 {
        // connect, accept
        ret = tcp_client_socket::connect(address, port, timeout);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        // client_hello, tls_accept
        ret = do_handshake();
        if (errorcode_t::success != ret) {
            __leave2;
        }
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            tcp_client_socket::close();
        }
    }
    return ret;
}

return_t tls_client_socket2::close() {
    return_t ret = errorcode_t::success;

    __try2 {
        auto session = &_session;

        binary_t bin;
        tls_record_application_data record(session);
        record.get_records().add(new tls_record_alert(session, tls_alertlevel_warning, tls_alertdesc_close_notify));
        record.write(from_client, bin);

        // tlsserver send close_notify
        // consume close_notify and close
        {
            const size_t bufsize = (1 << 16);
            char buffer[bufsize];

            size_t cbsent = 0;
            ret = tcp_client_socket::send((char*)&bin[0], bin.size(), &cbsent);

            size_t cbread = 0;
            auto test = tcp_client_socket::read(buffer, bufsize, &cbread);
            if ((errorcode_t::success == test) || (errorcode_t::more_data == test)) {
                binary_append(bin, buffer, cbread);
                while (errorcode_t::more_data == test) {
                    test = tcp_client_socket::more(buffer, bufsize, &cbread);
                    if (errorcode_t::more_data == test) {
                        binary_append(bin, buffer, cbread);
                    }
                }
            }

            size_t size = bin.size();
            if (size) {
                byte_t* stream = &bin[0];
                size_t pos = 0;
                while (pos < size) {
                    uint8 content_type = stream[pos];
                    tls_record_builder builder;
                    auto record = builder.set(session).set(content_type).build();
                    if (record) {
                        ret = record->read(from_server, stream, size, pos);
                        if (errorcode_t::success == ret) {
                            //
                        }
                        record->release();
                    }
                }
            }
        }

        ret = tcp_client_socket::close();
    }
    __finally2 {}

    return ret;
}

return_t tls_client_socket2::read(char* ptr_data, size_t size_data, size_t* cbread) {
    return_t ret = errorcode_t::success;
    *cbread = 0;

    auto session = &_session;
    binary_t bin;
    const size_t bufsize = (1 << 10);
    char buffer[bufsize];
    size_t sizeread = 0;

    auto test = tcp_client_socket::read(buffer, bufsize, &sizeread);
    if ((errorcode_t::success == test) || (errorcode_t::more_data == test)) {
        binary_append(bin, buffer, sizeread);
        while (errorcode_t::more_data == test) {
            test = tcp_client_socket::more(buffer, bufsize, &sizeread);
            if (errorcode_t::more_data == test) {
                binary_append(bin, buffer, sizeread);
            }
        }
    }

    size_t size = bin.size();
    if (size) {
        byte_t* stream = &bin[0];
        size_t pos = 0;
        while (pos < size) {
            uint8 content_type = stream[pos];
            tls_record_builder builder;
            auto record = builder.set(session).set(content_type).build();
            if (record) {
                ret = record->read(from_server, stream, size, pos);
                if (errorcode_t::success == ret) {
                    if (tls_content_type_application_data == content_type) {
                        // TODO
                    }
                }
                record->release();
            }
        }
    }
    return ret;
}

return_t tls_client_socket2::more(char* ptr_data, size_t size_data, size_t* cbread) {
    return_t ret = errorcode_t::success;
    // TODO
    return ret;
}

return_t tls_client_socket2::send(const char* ptr_data, size_t size_data, size_t* cbsent) {
    return_t ret = errorcode_t::success;

    auto session = &_session;
    binary_t bin;
    tls_record_application_data record(session);
    record.get_records().add(new tls_record_application_data(session, (byte_t*)ptr_data, size_data));
    record.write(from_client, bin);

    ret = tcp_client_socket::send((char*)&bin[0], bin.size(), cbsent);
    return ret;
}

return_t tls_client_socket2::do_handshake() {
    return_t ret = errorcode_t::success;
    const size_t bufsize = (1 << 16);
    char buffer[bufsize];

    __try2 {
        size_t cbsent = 0;
        binary_t bin;

        auto session = &_session;

        // client hello
        {
            tls_record_handshake record(session);
            tls_handshake_client_hello* handshake = nullptr;

            handshake = new tls_handshake_client_hello(session);

            // random
            {
                openssl_prng prng;

                binary_t random;  // gmt_unix_time(4 bytes) + random(28 bytes)
                binary_t temp;
                prng.random(temp, 32);
                handshake->set_random(random);

                binary_t session_id;
                prng.random(session_id, 32);
                handshake->set_session_id(session_id);
            }

            // cipher suites
            {
                handshake->add_ciphersuite(0x1301);
                handshake->add_ciphersuite(0x1302);
                handshake->add_ciphersuite(0x1303);
                handshake->add_ciphersuite(0x1304);
                handshake->add_ciphersuite(0x1305);
            }
            // {
            //     auto sni = new tls_extension_sni(session);
            //     auto& hostname = sni->get_hostname();
            //     hostname = "test.server.com";
            //     handshake->get_extensions().add(sni);
            // }
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
                auto extension = new tls_extension_unknown(tls1_ext_next_protocol_negotiation, session);
                handshake->get_extensions().add(extension);
            }
            {
                auto extension = new tls_extension_unknown(tls1_ext_encrypt_then_mac, session);
                handshake->get_extensions().add(extension);
            }
            {
                auto extension = new tls_extension_unknown(tls1_ext_extended_master_secret, session);
                handshake->get_extensions().add(extension);
            }
            {
                auto extension = new tls_extension_unknown(tls1_ext_post_handshake_auth, session);
                handshake->get_extensions().add(extension);
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
                (*supported_versions).add(tls_13);
                if (_minver < tls_13) {
                    (*supported_versions).add(tls_12);
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

            record.get_handshakes().add(handshake);
            ret = record.write(from_client, bin);
        }  // end of client hello

        ret = tcp_client_socket::send((char*)&bin[0], bin.size(), &cbsent);

        // server hello ... server finished
        bin.clear();

        size_t cbread = 0;
        auto test = tcp_client_socket::read(buffer, bufsize, &cbread);
        if ((errorcode_t::success == test) || (errorcode_t::more_data == test)) {
            binary_append(bin, buffer, cbread);
            while (errorcode_t::more_data == test) {
                test = tcp_client_socket::more(buffer, bufsize, &cbread);
                if (errorcode_t::more_data == test) {
                    binary_append(bin, buffer, cbread);
                }
            }
        }

        size_t size = bin.size();
        if (size) {
            byte_t* stream = &bin[0];
            size_t pos = 0;
            while (pos < size) {
                uint8 content_type = stream[pos];
                tls_record_builder builder;
                auto record = builder.set(session).set(content_type).build();
                if (record) {
                    ret = record->read(from_server, stream, size, pos);
                    if (errorcode_t::success == ret) {
                        //
                    }
                    record->release();
                }
            }
        }

        bin.clear();

        // client finished
        {
            tls_record_change_cipher_spec record(session);
            ret = record.write(from_client, bin);
        }

        {
            tls_record_application_data record(session);
            record.get_handshakes().add(new tls_handshake_finished(session));
            record.write(from_client, bin);
        }

        ret = tcp_client_socket::send((char*)&bin[0], bin.size(), &cbsent);
    }
    __finally2 {}

    return ret;
}

}  // namespace net
}  // namespace hotplace
