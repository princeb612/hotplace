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
#include <sdk/base/nostd/exception.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/stream/split.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/io/basic/payload.hpp>
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

dtls_record_publisher::dtls_record_publisher() : _session(nullptr), _fragment_size(1024), _segment_size(1200), _flags(0) {}

void dtls_record_publisher::set_fragment_size(uint16 size) {
    const uint16 minsize = 1 << 7;
    const uint16 maxsize = 1 << 10;
    adjust_range(size, minsize, maxsize);
    _fragment_size = size;
}

uint16 dtls_record_publisher::get_fragment_size() { return _fragment_size; }

void dtls_record_publisher::set_segment_size(uint16 size) { _segment_size = size; }

uint16 dtls_record_publisher::get_max_size() { return _segment_size; }

return_t dtls_record_publisher::publish(tls_record* record, tls_direction_t dir, std::list<binary_t>& container) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == record) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        __try2 {
            record->addref();

            tls_advisor* tlsadvisor = tls_advisor::get_instance();
            tls_record_builder builder;
            auto session = get_session();
            if (nullptr == session) {
                throw exception(no_session);
            } else {
                if (session_type_dtls != session->get_type()) {
                    throw exception(no_session);
                }
            }
            auto session_type = session->get_type();
            size_t hdrsize = sizeof(dtls_handshake_t);

            struct spl_desc {
                tls_hs_type_t hstype;
                uint16 hsseq;
            };

            splitter<spl_desc> spl;
            spl.set_segment_size(get_fragment_size());

            {
                auto rctype = record->get_type();
                auto& kv = session->get_session_info(dir).get_keyvalue();
                uint16 hsseq = kv.get(session_dtls_message_seq);

                std::list<tls_record*> records;

                auto lambda_handshake = [&](tls_handshake* handshake) -> return_t {
                    return_t ret = errorcode_t::success;
                    binary_t bin;
                    __try2 {
                        // generate body + update transcript hash
                        ret = handshake->write(dir, bin);
                        if (errorcode_t::success != ret) {
                            __leave2;
                        }
                        // and now trim handshake header
                        bin.erase(bin.begin(), bin.begin() + hdrsize);

                        auto hstype = handshake->get_type();

                        spl_desc desc;
                        desc.hstype = hstype;
                        desc.hsseq = hsseq;

#if defined DEBUG
                        if (istraceable(trace_category_net, loglevel_debug)) {
                            basic_stream dbs;
                            dbs.printf("\e[1;36m");
                            dbs.println("# publish %s %i %s", tlsadvisor->handshake_type_string(hstype).c_str(), hsseq,
                                        tlsadvisor->nameof_direction(dir, 1).c_str());
                            dbs.printf("\e[0m");
                            dump_memory(bin, &dbs, 16, 3, 0, dump_notrunc);
                            trace_debug_event(trace_category_net, trace_event_tls_record, &dbs);
                        }
#endif
                        spl.add(std::move(bin), std::move(desc));

                        ++hsseq;
                    }
                    __finally2 {}
                    return ret;
                };

                auto lambda_split = [&](uint32 flags, const byte_t* stream, size_t size, size_t fragoffset, size_t fragsize, const spl_desc& desc) -> void {
#if defined DEBUG
                    if (istraceable(trace_category_net, loglevel_debug)) {
                        basic_stream dbs;
                        dbs.printf("\e[1;36m");
                        dbs.println("# split %s %i %s", tlsadvisor->handshake_type_string(desc.hstype).c_str(), desc.hsseq,
                                    tlsadvisor->nameof_direction(dir, 1).c_str());
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
                    // rec_handshake->set_flags(dont_control_dtls_sequence);  // do not change epoch, sequence (record)

                    // split handshake
                    ret = rec_handshake->get_handshakes().for_each(lambda_handshake);
                    if (errorcode_t::success != ret) {
                        __leave2;
                    }
                    // generate record
                    spl.run(lambda_split);

                    // write record
                    for (auto item : records) {
                        binary_t bin;
                        item->write(dir, bin);
                        container.push_back(bin);
                        item->release();
                    }
                } else {
                    binary_t bin;
                    ret = record->write(dir, bin);
                    container.push_back(bin);
                }
            }
        }
        __finally2 { record->release(); }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t dtls_record_publisher::publish(tls_record* record, tls_direction_t dir, std::function<void(tls_session*, binary_t&)> func) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == record || nullptr == func) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        std::list<binary_t> container;
        ret = publish(record, dir, container);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        for (auto& item : container) {
            func(get_session(), item);
        }
    }
    __finally2 {}
    return ret;
}

return_t dtls_record_publisher::publish(tls_records* records, tls_direction_t dir, std::function<void(tls_session*, binary_t&)> func) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == records || nullptr == func) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        std::list<binary_t> container;
        std::list<std::queue<binary_t>> temp;
        std::queue<binary_t> q;
        size_t size = 0;
        auto lambda = [&](tls_record* record) -> return_t { return publish(record, dir, container); };
        ret = records->for_each(lambda);

        for (auto& item : container) {
            auto isize = item.size();
            if (size + isize > get_max_size()) {
                temp.push_back(std::move(q));
                size = 0;
            }
            q.push(std::move(item));
            size += isize;
        }
        if (false == q.empty()) {
            temp.push_back(std::move(q));
        }

        for (auto& qitem : temp) {
            auto qsize = qitem.size();
            if (1 == qsize) {
                func(get_session(), qitem.front());
                qitem.pop();
            } else {
                binary_t bin;
                for (; false == qitem.empty(); qitem.pop()) {
                    binary_append(bin, qitem.front());
                }
                func(get_session(), bin);
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

void dtls_record_publisher::set_session(tls_session* session) {
    if (nullptr == session) {
        throw exception(no_session);
    }

    _session = session;
}

tls_session* dtls_record_publisher::get_session() { return _session; }

void dtls_record_publisher::set_flags(uint32 flags) { _flags = flags; }

uint32 dtls_record_publisher::get_flags() { return _flags; }

}  // namespace net
}  // namespace hotplace
