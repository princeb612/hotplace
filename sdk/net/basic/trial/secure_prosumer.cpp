/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/unittest/trace.hpp>
#include <hotplace/sdk/net/basic/trial/secure_prosumer.hpp>
#include <hotplace/sdk/net/tls/dtls_record_arrange.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record_application_data.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record_builder.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_protection.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

secure_prosumer::secure_prosumer() {}

return_t secure_prosumer::produce(tls_session* session, tls_direction_t dir, std::function<void(basic_stream&, sockaddr_storage_t&)> func) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == func) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        sockaddr_storage_t addr;
        func(_mbs, addr);

        socklen_t addrlen = sizeof(addr);
        ret = do_produce(session, dir, (sockaddr*)&addr, &addrlen);
    }
    __finally2 {}
    return ret;
}

return_t secure_prosumer::produce(tls_session* session, tls_direction_t dir, const byte_t* ptr_data, size_t size_data, struct sockaddr* addr,
                                  socklen_t* addrlen) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == ptr_data) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        _mbs.write((byte_t*)ptr_data, size_data);

        ret = do_produce(session, dir, addr, addrlen);
    }
    __finally2 {}
    return ret;
}

return_t secure_prosumer::do_produce(tls_session* session, tls_direction_t dir, struct sockaddr* addr, socklen_t* addrlen) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_record_builder builder;

        auto session_type = session->get_type();
        size_t pos = 0;

        if (session_type_dtls == session_type) {
            // DTLS (built-in reorder feature)
            if (nullptr == addr || nullptr == addrlen) {
                ret = errorcode_t::invalid_parameter;
                __leave2;
            }
            socklen_t socklen = *addrlen;

            auto& arrange = session->get_dtls_record_arrange();
            arrange.produce(addr, socklen, _mbs.data(), _mbs.size());
            _mbs.clear();

            while (1) {
                binary_t packet;
                auto test = arrange.consume(addr, socklen, packet);
                if (success == test) {
                    pos = 0;
                    ret = do_produce(session, dir, &packet[0], packet.size(), pos, addr, addrlen);
                } else {
                    break;  // empty, not_ready
                }
            }
        } else {
            // TLS, QUIC
            const byte_t* stream = _mbs.data();
            size_t size = _mbs.size();
            ret = do_produce(session, dir, stream, size, pos, addr, addrlen);
            _mbs.cut(0, pos);
        }
    }
    __finally2 {}
    return ret;
}

return_t secure_prosumer::do_produce(tls_session* session, tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, struct sockaddr* addr,
                                     socklen_t* addrlen) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_record_builder builder;

        while ((errorcode_t::success == ret) && (pos < size)) {
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
                            if (addr && addrlen) {
                                memcpy(&item.addr, addr, *addrlen);
                            }

                            critical_section_guard guard(_mlock);
                            _mq.push(std::move(item));

                            _msem.signal();
                        }
                    }
                }
                record->release();
            }
        }
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
                if (addr && addrlen) {
                    memcpy(addr, &item.addr, *addrlen);
                }
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
#if defined DEBUG
            if (*cbread) {
                if (istraceable(trace_category_net)) {
                    trace_debug_event(trace_category_net, trace_event_tls_record, [&](basic_stream& dbs) -> void {
                        dbs.println("+ read");
                        dump_memory((byte_t*)ptr_data, *cbread, &dbs, 16, 3, 0x0, dump_notrunc);
                    });
                }
            }
#endif
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
