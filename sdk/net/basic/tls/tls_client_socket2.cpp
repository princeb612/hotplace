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
#include <sdk/crypto/basic/openssl_prng.hpp>
#include <sdk/net/basic/tls/tls_client_socket2.hpp>
#include <sdk/net/basic/tls/tls_composer.hpp>
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
#include <sdk/net/tls/tls/handshake/tls_handshake_server_hello_done.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake_server_key_exchange.hpp>
#include <sdk/net/tls/tls/record/tls_record_alert.hpp>
#include <sdk/net/tls/tls/record/tls_record_application_data.hpp>
#include <sdk/net/tls/tls/record/tls_record_builder.hpp>
#include <sdk/net/tls/tls/record/tls_record_change_cipher_spec.hpp>
#include <sdk/net/tls/tls/record/tls_record_handshake.hpp>
#include <sdk/net/tls/tls/tls.hpp>
#include <sdk/net/tls/tls_advisor.hpp>

namespace hotplace {
namespace net {

tls_client_socket2::tls_client_socket2(tls_version_t minver) : async_client_socket(), _version(minver) {
    auto session = &_session;
    session->set_type(session_tls);
}

return_t tls_client_socket2::send(const char* ptr_data, size_t size_data, size_t* cbsent) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == ptr_data || nullptr == cbsent) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        *cbsent = 0;

        auto session = &_session;

        binary_t bin;
        tls_record_application_data record(session);
        record.get_records().add(new tls_record_application_data(session, (byte_t*)ptr_data, size_data));
        record.write(from_client, bin);

        size_t sent = 0;
        ret = async_client_socket::send((char*)&bin[0], bin.size(), &sent);
        if (errorcode_t::success == ret) {
            *cbsent = size_data;
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_client_socket2::do_handshake() {
    return_t ret = errorcode_t::success;
    const size_t bufsize = (1 << 16);
    char buffer[bufsize];
    tls_advisor* tlsadvisor = tls_advisor::get_instance();

    __try2 {
        size_t cbsent = 0;
        binary_t bin;
        uint32 session_status = 0;

        auto session = &_session;
        auto& protection = session->get_tls_protection();
        tls_direction_t dir = from_client;

        tls_composer composer(session);
        composer.set_minver(_version);
        composer.set_maxver(_version);

        auto lambda = [&](binary_t& bin) -> void {
            ret = async_client_socket::send((char*)&bin[0], bin.size(), &cbsent);
            bin.clear();
        };

        ret = composer.handshake(from_client, get_wto(), lambda);
    }
    __finally2 {}

    return ret;
}

return_t tls_client_socket2::do_read(char* ptr_data, size_t size_data, size_t* cbread, struct sockaddr* addr, socklen_t* addrlen) {
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

return_t tls_client_socket2::do_secure() {
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

return_t tls_client_socket2::do_shutdown() {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = &_session;

        binary_t bin;
        size_t cbsent = 0;

        {
            auto dir = from_client;
            tls_record_builder builder;
            auto record = builder.set(session).set(tls_content_type_alert).set(dir).construct().build();

            *record << new tls_record_alert(session, tls_alertlevel_warning, tls_alertdesc_close_notify);
            record->write(dir, bin);
            record->release();
        }

        ret = async_client_socket::send((char*)&bin[0], bin.size(), &cbsent);

        // session->wait_change_session_status(session_server_close_notified, get_wto());
        // auto session_status = session->get_session_status();
    }
    __finally2 {}
    return ret;
}

tls_session& tls_client_socket2::get_session() { return _session; }

bool tls_client_socket2::support_tls() { return true; }

int tls_client_socket2::socket_type() { return SOCK_STREAM; }

}  // namespace net
}  // namespace hotplace
