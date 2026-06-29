/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   dtls_record_arrange.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/nostd/enumclass.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/basic/ipaddr/sdk.hpp>
#include <hotplace/sdk/net/tls/dtls_record_arrange.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_protection.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>
#include <hotplace/sdk/net/tls/types.hpp>

namespace hotplace {
namespace net {

dtls_record_arrange::dtls_record_arrange() {}

dtls_record_arrange::~dtls_record_arrange() {}

return_t dtls_record_arrange::produce(const sockaddr* addr, socklen_t addrlen, const byte_t* stream, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == addr || nullptr == stream || size < sizeof(dtls_header)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        binary_t cookie;
        ret = generate_cookie_sockaddr(cookie, addr, addrlen);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        size_t pos = 0;
        tls_advisor* tlsadvisor = tls_advisor::get_instance();

        while ((pos < size) && (errorcode_t::success == ret)) {
            if (pos + sizeof(dtls_header) > size) {
                ret = errorcode_t::bad_data;
                break;
            }

            dtls_header* header = (dtls_header*)(stream + pos);

            uint16 version = ntoh16(header->version);
            t_enum_type<tls_version_t> etversion(version);
            if (false == tlsadvisor->is_kindof_dtls(etversion)) {
                ret = errorcode_t::bad_data;
                break;
            }
            uint16 len = ntoh16(header->length);

            if (pos + sizeof(dtls_header) + len > size) {
                ret = errorcode_t::bad_data;
                break;
            }

            uint16 epoch = ntoh16(header->keyepoch);
            uint64 seq = uint48_t(header->recordseq, 6);  // 6 bytes
            uint64 key = make_epoch_seq(epoch, seq);

            {
                critical_section_guard guard(_lock);
                auto iter = _pool.find(cookie);
                if (_pool.end() != iter) {
                    auto& pool = iter->second;
                    if (((epoch == pool.epoch) && (seq < pool.seq)) || ((epoch < pool.epoch))) {
                        // drop re-transmission
                        pos += sizeof(dtls_header) + len;
                        continue;
                    }

                    if (pool.packets.size() >= 100) {
                        // MAX_WINDOW_SIZE
                        pos += sizeof(dtls_header) + len;
                        continue;
                    }
                }

                auto& pool = _pool[cookie];
                if (0 == pool.addr.ss_family) {
                    memcpy(&pool.addr, addr, addrlen);
                }
#if defined DEBUG
                if (istraceable(trace_category_t::trace_category_net)) {
                    trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_tls_record,
                                      [&](basic_stream& dbs) -> void { dbs.println(ANSI_ESCAPE "1;35mDTLS reorder + epoch %u seq %I64u" ANSI_ESCAPE "0m", epoch, seq); });
                }
#endif

                binary_t& packet = pool.packets[key];
                packet.clear();
                binary_append(packet, stream + pos, sizeof(dtls_header) + len);
            }

            pos += sizeof(dtls_header) + len;
        }
    }
    __finally2 {}
    return ret;
}

return_t dtls_record_arrange::consume(const sockaddr* addr, socklen_t addrlen, binary_t& bin) {
    uint16 epoch = 0;
    uint64 seq = 0;
    return consume(addr, addrlen, epoch, seq, bin);
}

return_t dtls_record_arrange::consume(const sockaddr* addr, socklen_t addrlen, uint16& epoch, uint64& seq, binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == addr) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        epoch = 0;
        seq = 0;
        bin.clear();

        binary_t cookie;
        ret = generate_cookie_sockaddr(cookie, addr, addrlen);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        critical_section_guard guard(_lock);
        {
            auto& pool = _pool[cookie];

            auto& packets = pool.packets;
            if (packets.empty()) {
                ret = errorcode_t::empty;
                __leave2;
            }

            auto iter = packets.begin();
            {
                auto& key = iter->first;
                get_epoch_seq(key, epoch, seq);

                if ((pool.epoch != epoch) || (pool.seq != seq)) {
                    ret = errorcode_t::not_ready;
                    __leave2;
                }

#if defined DEBUG
                if (istraceable(trace_category_t::trace_category_net)) {
                    trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_tls_record,
                                      [&](basic_stream& dbs) -> void { dbs.println(ANSI_ESCAPE "1;35mDTLS reorder ! epoch %u seq %I64u" ANSI_ESCAPE "0m", epoch, seq); });
                }
#endif

                const binary_t& packet = iter->second;
                auto type = packet[0];
                t_enum_type<tls_content_type_t> ettype(type);
                if (tls_content_type_t::change_cipher_spec == ettype) {
                    pool.epoch++;
                    pool.seq = 0;
                } else {
                    pool.epoch = epoch;
                    pool.seq = seq + 1;
                }

                bin = std::move(iter->second);

                packets.erase(iter);
            }
        }
    }
    __finally2 {}
    return ret;
}

uint64 dtls_record_arrange::make_epoch_seq(uint16 epoch, uint64 seq) { return (static_cast<uint64>(epoch) << 48) | (seq & 0x0000FFFFFFFFFFFFULL); }

void dtls_record_arrange::get_epoch_seq(uint64 key, uint16& epoch, uint64& seq) {
    epoch = static_cast<uint16>(key >> 48);
    seq = key & 0x0000FFFFFFFFFFFFULL;
}

void dtls_record_arrange::set_session(tls_session* session) { _session = session; }

tls_session* dtls_record_arrange::get_session() { return _session; }

}  // namespace net
}  // namespace hotplace
