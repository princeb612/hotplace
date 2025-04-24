/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *          RFC 8446 The Transport Layer Security (TLS) Protocol Version 1.3
 *          RFC 6066 Transport Layer Security (TLS) Extensions: Extension Definitions
 *          RFC 5246 The Transport Layer Security (TLS) Protocol Version 1.2
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/dtls_record_reorder.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_protection.hpp>
#include <sdk/net/tls/tls_session.hpp>
#include <sdk/net/tls/types.hpp>

namespace hotplace {
namespace net {

dtls_record_reorder::dtls_record_reorder() : _epoch(0), _seq(0) {}

dtls_record_reorder::~dtls_record_reorder() {}

return_t dtls_record_reorder::produce(const byte_t* stream, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == stream || size < sizeof(dtls_header)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        size_t pos = 0;
        tls_advisor* tlsadvisor = tls_advisor::get_instance();

        while (pos < size) {
            dtls_header* header = (dtls_header*)(stream + pos);

            // uint8 type = header->type;
            uint16 version = ntoh16(header->version);
            if (false == is_kindof_dtls(version)) {
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
                _packets.insert({key, packet});
            }

            pos += sizeof(dtls_header) + len;
        }
    }
    __finally2 {}
    return ret;
}

return_t dtls_record_reorder::consume(binary_t& bin) {
    uint16 epoch = 0;
    uint64 seq = 0;
    return consume(epoch, seq, bin);
}

return_t dtls_record_reorder::consume(uint16& epoch, uint64& seq, binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        epoch = 0;
        seq = 0;
        bin.clear();

        {
            critical_section_guard guard(_lock);
            if (_packets.empty()) {
                ret = errorcode_t::empty;
                __leave2;
            }

            auto iter = _packets.begin();
            get_epoch_seq(iter->first, epoch, seq);

            if ((_epoch != epoch) || (_seq != seq)) {
                ret = errorcode_t::not_ready;
            }
            if (errorcode_t::success != ret) {
                __leave2;
            }

            const binary_t& packet = iter->second;
            if (tls_content_type_change_cipher_spec == packet[0]) {
                _epoch++;
                _seq = 0;
            } else {
                _epoch = epoch;
                _seq = seq + 1;
            }

            bin = std::move(iter->second);

            _packets.erase(iter);
        }
    }
    __finally2 {}
    return ret;
}

uint64 dtls_record_reorder::make_epoch_seq(uint16 epoch, uint64 seq) {
    uint64 value = 0;
    uint16 e = hton16(epoch);
    uint48_t s(seq);
    memcpy((byte_t*)&value, &e, 2);
    memcpy((byte_t*)&value + 2, s.data, 6);
    return ntoh64(value);
}

void dtls_record_reorder::get_epoch_seq(uint64 key, uint16& epoch, uint64& seq) {
    uint16 etemp = 0;
    uint64 stemp = hton64(key);

    memcpy((byte_t*)&etemp, (byte_t*)&stemp, 2);
    epoch = ntoh16(etemp);

    uint48_t s;
    memcpy(s.data, (byte_t*)&stemp + 2, 6);
    seq = s;
}

void dtls_record_reorder::set_session(tls_session* session) { _session = session; }

tls_session* dtls_record_reorder::get_session() { return _session; }

}  // namespace net
}  // namespace hotplace
