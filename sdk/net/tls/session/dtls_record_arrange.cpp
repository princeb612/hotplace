/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/unittest/trace.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/basic/util/sdk.hpp>
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

        while (pos < size) {
            dtls_header* header = (dtls_header*)(stream + pos);

            // uint8 type = header->type;
            uint16 version = ntoh16(header->version);
            if (false == tlsadvisor->is_kindof_dtls(version)) {
                ret = errorcode_t::bad_data;
                __leave2;
            }
            uint16 len = ntoh16(header->length);

            uint16 epoch = ntoh16(header->keyepoch);
            uint64 seq = uint48_t(header->recordseq, 6);
            uint64 key = make_epoch_seq(epoch, seq);
            binary_t packet;
            binary_append(packet, stream + pos, sizeof(dtls_header) + len);

            {
                critical_section_guard guard(_lock);
                auto& pool = _pool[cookie];
                memcpy(&pool.addr, addr, addrlen);
                pool.packets.insert({key, std::move(packet)});
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

                const binary_t& packet = iter->second;
                if (tls_content_type_change_cipher_spec == packet[0]) {
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

uint64 dtls_record_arrange::make_epoch_seq(uint16 epoch, uint64 seq) {
    uint64 value = 0;
    uint16 e = hton16(epoch);
    uint48_t s(seq);
    memcpy((byte_t*)&value, &e, 2);
    memcpy((byte_t*)&value + 2, s.data, 6);
    return ntoh64(value);
}

void dtls_record_arrange::get_epoch_seq(uint64 key, uint16& epoch, uint64& seq) {
    uint16 etemp = 0;
    uint64 stemp = hton64(key);

    memcpy((byte_t*)&etemp, (byte_t*)&stemp, 2);
    epoch = ntoh16(etemp);

    uint48_t s;
    memcpy(s.data, (byte_t*)&stemp + 2, 6);
    seq = s;
}

void dtls_record_arrange::set_session(tls_session* session) { _session = session; }

tls_session* dtls_record_arrange::get_session() { return _session; }

}  // namespace net
}  // namespace hotplace
