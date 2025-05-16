/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/basic/sdk/secure_prosumer.hpp>
#include <sdk/net/tls/tls/record/tls_record.hpp>
#include <sdk/net/tls/tls/record/tls_record_application_data.hpp>
#include <sdk/net/tls/tls/record/tls_record_builder.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_protection.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

secure_prosumer::secure_prosumer() {}

return_t secure_prosumer::produce(tls_session* session, tls_direction_t dir, std::function<void(basic_stream&)> func) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == func) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        func(_mbs);

        ret = do_produce(session, dir);
    }
    __finally2 {}
    return ret;
}

return_t secure_prosumer::produce(tls_session* session, tls_direction_t dir, const byte_t* ptr_data, size_t size_data) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == ptr_data) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        _mbs.write((byte_t*)ptr_data, size_data);
        ret = do_produce(session, dir);
    }
    __finally2 {}
    return ret;
}

return_t secure_prosumer::do_produce(tls_session* session, tls_direction_t dir) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_record_builder builder;

        const byte_t* stream = _mbs.data();
        size_t size = _mbs.size();
        size_t pos = 0;
        while (pos < size) {
            uint8 content_type = stream[pos];
            auto record = builder.set(session).set(content_type).build();
            if (record) {
                ret = record->read(dir, stream, size, pos);
                if (errorcode_t::success == ret) {
                    if (tls_content_type_application_data == content_type) {
                        tls_record_application_data* appdata = (tls_record_application_data*)record;
                        const auto& bin = appdata->get_binary();

                        if (false == bin.empty()) {
                            socket_buffer_t item;
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
    __finally2 {}
    return ret;
}

return_t secure_prosumer::consume(int sock_type, uint32 wto, char* ptr_data, size_t size_data, size_t* cbread, struct sockaddr* addr, socklen_t* addrlen) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == ptr_data || nullptr == cbread) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        *cbread = 0;

        ret = _msem.wait(wto);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        critical_section_guard guard(_mlock);
        if (false == _mq.empty()) {
            auto& item = _mq.front();

            if (SOCK_DGRAM == sock_type) {
                memcpy(addr, &item.addr, sizeof(sockaddr_storage_t));
            }

            auto datasize = item.buffer.size();
            if (datasize >= size_data) {
                memcpy(ptr_data, item.buffer.data(), size_data);
                item.buffer.cut(0, size_data);

                *cbread = size_data;
            } else {
                memcpy(ptr_data, item.buffer.data(), datasize);

                *cbread = datasize;

                _mq.pop();
            }
            if (false == _mq.empty()) {
                ret = errorcode_t::more_data;
            }
        } else {
            ret = errorcode_t::empty;
        }
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
