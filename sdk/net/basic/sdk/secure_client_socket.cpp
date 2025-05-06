/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/basic/sdk/secure_client_socket.hpp>
#include <sdk/net/basic/sdk/tls_composer.hpp>
#include <sdk/net/tls/tls/record/tls_record_alert.hpp>
#include <sdk/net/tls/tls/record/tls_record_application_data.hpp>
#include <sdk/net/tls/tls/record/tls_record_builder.hpp>
#include <sdk/net/tls/tls/tls.hpp>
#include <sdk/net/tls/tls_advisor.hpp>

namespace hotplace {
namespace net {

secure_client_socket::secure_client_socket(tls_version_t version) : async_client_socket(), _version(version) {}

return_t secure_client_socket::do_handshake() {
    return_t ret = errorcode_t::success;
    tls_advisor* tlsadvisor = tls_advisor::get_instance();

    __try2 {
        tls_composer composer(get_session());
        composer.set_minver(_version);
        composer.set_maxver(_version);

        auto lambda = [&](binary_t& bin) -> void { do_send(bin); };
        ret = composer.handshake(from_client, get_wto(), lambda);
    }
    __finally2 {}

    return ret;
}

return_t secure_client_socket::do_read(char* ptr_data, size_t size_data, size_t* cbread, struct sockaddr* addr, socklen_t* addrlen) {
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

return_t secure_client_socket::do_secure() {
    return_t ret = errorcode_t::success;
    auto type = socket_type();
    tls_direction_t dir = from_server;
    tls_record_builder builder;

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
            auto record = builder.set(get_session()).set(content_type).build();
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

#if 0
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

        do_send(bin);
    }
#endif

    return ret;
}

return_t secure_client_socket::do_shutdown() {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();

        binary_t bin;

        {
            auto dir = from_client;
            tls_record_builder builder;
            auto record = builder.set(session).set(tls_content_type_alert).set(dir).construct().build();

            *record << new tls_record_alert(session, tls_alertlevel_warning, tls_alertdesc_close_notify);
            record->write(dir, bin);
            record->release();
        }

        do_send(bin);

        session->wait_change_session_status(session_status_server_close_notified, get_wto());
        auto session_status = session->get_session_status();
    }
    __finally2 {}
    return ret;
}

/* override */
return_t secure_client_socket::do_send(binary_t& bin) { return errorcode_t::success; }

tls_session* secure_client_socket::get_session() { return &_session; }

tls_version_t secure_client_socket::get_version() { return _version; }

bool secure_client_socket::support_tls() { return true; }

}  // namespace net
}  // namespace hotplace
