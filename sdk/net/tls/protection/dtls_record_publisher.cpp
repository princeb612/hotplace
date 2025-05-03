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

#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/io/stream/split.hpp>
#include <sdk/net/tls/dtls_record_publisher.hpp>
#include <sdk/net/tls/tls/handshake/dtls_handshake_fragmented.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake.hpp>
#include <sdk/net/tls/tls/record/tls_record.hpp>
#include <sdk/net/tls/tls/record/tls_record_builder.hpp>
#include <sdk/net/tls/tls/record/tls_record_handshake.hpp>
#include <sdk/net/tls/tls/record/tls_records.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_protection.hpp>
#include <sdk/net/tls/tls_session.hpp>
#include <sdk/net/tls/types.hpp>

namespace hotplace {
namespace net {

dtls_record_publisher::dtls_record_publisher() : _session(nullptr), _fragment_size(1024), _flags(0) {}

void dtls_record_publisher::set_fragment_size(uint16 size) {
    const uint16 minsize = 1 << 7;
    const uint16 maxsize = 1 << 10;
    adjust_range(size, minsize, maxsize);
    _fragment_size = size;
}

uint16 dtls_record_publisher::get_fragment_size() { return _fragment_size; }

return_t dtls_record_publisher::publish(tls_record* record, tls_direction_t dir, std::function<void(binary_t& bin)> func) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == record || nullptr == func) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        tls_record_builder builder;
        auto session = get_session();

        struct spl_desc {
            tls_hs_type_t hstype;
            uint16 hsseq;
        };
        splitter<spl_desc> spl;

        {
            auto rctype = record->get_type();
            auto& kv = session->get_session_info(dir).get_keyvalue();
            uint16 hsseq = kv.get(session_dtls_message_seq);

            std::list<tls_record*> records;

            auto lambda_handshake = [&](tls_handshake* handshake) -> void {
                binary_t bin;
                handshake->do_write_body(dir, bin);

                spl_desc desc;
                desc.hstype = handshake->get_type();
                desc.hsseq = hsseq;

#if defined DEBUG
                if (check_trace_level(loglevel_debug) && istraceable()) {
                    basic_stream dbs;
                    dbs.printf("\e[1;36m");
                    dbs.println("# publish %s %i %s", tlsadvisor->handshake_type_string(desc.hstype).c_str(), desc.hsseq,
                                tlsadvisor->nameof_direction(dir, true).c_str());
                    dbs.printf("\e[0m");
                    dump_memory(bin, &dbs, 16, 3, 0, dump_notrunc);
                    trace_debug_event(trace_category_net, trace_event_tls_record, &dbs);
                }
#endif

                spl.add(std::move(bin), std::move(desc));

                ++hsseq;
            };

            auto lambda_split = [&](uint32 flags, const byte_t* stream, size_t size, size_t fragoffset, size_t fragsize, const spl_desc& desc) -> void {
#if defined DEBUG
                if (check_trace_level(loglevel_debug) && istraceable()) {
                    basic_stream dbs;
                    dbs.printf("\e[1;36m");
                    dbs.println("# split %s %i %s", tlsadvisor->handshake_type_string(desc.hstype).c_str(), desc.hsseq,
                                tlsadvisor->nameof_direction(dir, true).c_str());
                    dbs.printf("\e[0m");
                    dump_memory(stream + fragoffset, fragsize, &dbs, 16, 3, 0, dump_notrunc);
                    trace_debug_event(trace_category_net, trace_event_tls_record, &dbs);
                }
#endif
                uint32 mask = splitter_flag_t::splitter_new_segment;
                if (dtls_record_publisher_multi_handshakes & get_flags()) {
                    // record consist of handshakes in the segment
                } else {
                    // each handshake starts a new record (easy to control max record size)
                    mask |= splitter_flag_t::splitter_new_group;
                }
                if (mask & flags) {
                    auto rec_built = builder.set(session).set(rctype).set(dir).construct().build();
                    records.push_back(rec_built);
                }
                auto rec_fragmented = *records.rbegin();
                auto hs_fragmented = new dtls_handshake_fragmented(desc.hstype, session);  // do not change sequence (handshake)
                hs_fragmented->prepare_fragment(stream, size, desc.hsseq, fragoffset, fragsize);
                *rec_fragmented << hs_fragmented;
            };

            if (tls_content_type_handshake == rctype) {
                tls_record_handshake* rec_handshake = static_cast<tls_record_handshake*>(record);
                rec_handshake->set_flags(dont_control_dtls_sequence);  // do not change epoch, sequence (record)
                rec_handshake->get_handshakes().for_each(lambda_handshake);

                spl.run(lambda_split);

                for (auto item : records) {
                    binary_t bin;
                    item->write(dir, bin);
                    func(bin);
                    item->release();
                }

                binary_t bin_record;
                rec_handshake->write(dir, bin_record);  // transcript hash, key calcuration
            } else {
                record->addref();

                binary_t bin;
                record->write(dir, bin);

                func(bin);
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t dtls_record_publisher::publish(tls_records* records, tls_direction_t dir, std::function<void(binary_t& bin)> func) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == records) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        auto lambda = [&](tls_record* record) -> void { publish(record, dir, func); };
        records->for_each(lambda);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

void dtls_record_publisher::set_session(tls_session* session) { _session = session; }

tls_session* dtls_record_publisher::get_session() { return _session; }

void dtls_record_publisher::set_flags(uint32 flags) { _flags = flags; }

uint32 dtls_record_publisher::get_flags() { return _flags; }

}  // namespace net
}  // namespace hotplace
