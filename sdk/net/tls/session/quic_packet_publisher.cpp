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
#include <hotplace/sdk/crypto/basic/openssl_prng.hpp>
#include <hotplace/sdk/net/basic/trial/tls_composer.hpp>
#include <hotplace/sdk/net/http/http3/http3_frame_builder.hpp>
#include <hotplace/sdk/net/http/http3/types.hpp>
#include <hotplace/sdk/net/tls/quic/frame/quic_frame_ack.hpp>
#include <hotplace/sdk/net/tls/quic/frame/quic_frame_builder.hpp>
#include <hotplace/sdk/net/tls/quic/frame/quic_frame_crypto.hpp>
#include <hotplace/sdk/net/tls/quic/frame/quic_frame_http3_stream.hpp>
#include <hotplace/sdk/net/tls/quic/frame/quic_frame_padding.hpp>
#include <hotplace/sdk/net/tls/quic/frame/quic_frame_stream.hpp>
#include <hotplace/sdk/net/tls/quic/frame/quic_frames.hpp>
#include <hotplace/sdk/net/tls/quic/packet/quic_packet_builder.hpp>
#include <hotplace/sdk/net/tls/quic_packet_publisher.hpp>
#include <hotplace/sdk/net/tls/quic_session.hpp>
#include <hotplace/sdk/net/tls/sdk.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_builder.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_protection.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>
#include <hotplace/sdk/net/tls/types.hpp>

namespace hotplace {
namespace net {

quic_packet_publisher::quic_packet_publisher() : _session(nullptr), _payload_size(0), _flags(0) {}

quic_packet_publisher::~quic_packet_publisher() {}

quic_packet_publisher& quic_packet_publisher::set_session(tls_session* session) {
    _session = session;
    if (session) {
        set_payload_size(session->get_quic_session().get_setting().get(quic_param_max_udp_payload_size));
    }
    return *this;
}

quic_packet_publisher& quic_packet_publisher::set_payload_size(uint16 size) {
    _payload_size = size;
    return *this;
}

quic_packet_publisher& quic_packet_publisher::set_flags(uint32 flags) {
    _flags = flags;
    return *this;
}

tls_session* quic_packet_publisher::get_session() { return _session; }

uint16 quic_packet_publisher::get_payload_size() { return _payload_size; }

uint32 quic_packet_publisher::get_flags() { return _flags; }

tls_handshakes& quic_packet_publisher::get_handshakes() { return _handshakes; }

quic_packet_publisher& quic_packet_publisher::add(tls_hs_type_t type, tls_direction_t dir, std::function<return_t(tls_handshake*, tls_direction_t)> func) {
    return_t ret = errorcode_t::success;
    tls_handshake* handshake = nullptr;
    auto session = get_session();
    switch (type) {
        case tls_hs_client_hello: {
            ret = tls_composer::construct_client_hello(&handshake, session, func, tls_13, tls_13);
        } break;
        case tls_hs_server_hello: {
            ret = tls_composer::construct_server_hello(&handshake, session, func, tls_13, tls_13);
        } break;
        default: {
            tls_handshake_builder builder;
            handshake = builder.set(type).set(session).build();
            if (handshake) {
                if (func) {
                    ret = func(handshake, dir);
                }
            }
        } break;
    }
    if (errorcode_t::success == ret) {
        _handshakes.add(handshake);
    } else {
        if (handshake) {
            handshake->release();
        }
    }
    return *this;
}

quic_packet_publisher& quic_packet_publisher::add(quic_frame_t type, std::function<return_t(quic_frame*)> func) {
    auto session = get_session();
    switch (type) {
        case quic_frame_type_crypto:
        case quic_frame_type_stream:
        case quic_frame_type_stream1:
        case quic_frame_type_stream2:
        case quic_frame_type_stream3:
        case quic_frame_type_stream4:
        case quic_frame_type_stream5:
        case quic_frame_type_stream6:
        case quic_frame_type_stream7: {
            // do nothing
        } break;
        default: {
            frame_entry_t entry;
            entry.how = frame_entry_quic;
            entry.type = type;
            entry.func = func;
            _frame_layout.push_back(std::move(entry));
        } break;
    }
    return *this;
}

quic_packet_publisher& quic_packet_publisher::add_stream(uint64 stream_id, uint8 uni_type, h3_frame_t type, std::function<return_t(http3_frame*)> func) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        http3_frame_builder builder;
        auto frame = builder.set(type).set(session).build();
        if (frame) {
            ret = func(frame);
            if (errorcode_t::success == ret) {
                frame_entry_t entry;
                entry.how = frame_entry_h3frame;
                entry.stream_id = stream_id;
                entry.uni_stream_type = uni_type;
                entry.frame = frame;
                _frame_layout.push_back(std::move(entry));
            } else {
                frame->release();
            }
        }
    }
    __finally2 {}
    return *this;
}

quic_packet_publisher& quic_packet_publisher::add_stream(uint64 stream_id, uint8 uni_type, std::function<return_t(qpack_stream&)> func) {
    __try2 {
        auto session = get_session();

        quic_frame_builder builder;
        auto frame = builder.set(quic_frame_type_stream).set(session).build();
        if (frame) {
            frame_entry_t entry;
            entry.how = frame_entry_qpack;
            entry.type = quic_frame_type_stream;
            entry.stream_id = stream_id;
            entry.uni_stream_type = uni_type;
            if (func) {
                qpack_stream qp;
                auto& dyntable = session->get_quic_session().get_dynamic_table();
                qp.set_dyntable(&dyntable);
                func(qp);
                entry.bin = std::move(qp.get_binary());
            }
            _frame_layout.push_back(std::move(entry));
        }
    }
    __finally2 {}
    return *this;
}

return_t quic_packet_publisher::probe_spaces(std::set<protection_space_t>& spaces) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (get_handshakes().size()) {
            std::set<protection_space_t> temp;
            ret = get_handshakes().for_each([&](tls_handshake* handshake) -> return_t {
                protection_space_t space;
                auto test = kindof_handshake(handshake, space);
                temp.insert(space);
                return (1 == temp.size()) ? success : bad_request;
            });
            if (errorcode_t::success != ret) {
                __leave2;
            }

            spaces = temp;
        }

        if (_frame_layout.size()) {
            spaces.insert(protection_application);
        }

        if (quic_ack_packet & get_flags()) {
            auto lambda_ack = [&](tls_session* session, protection_space_t space) -> return_t {
                auto& pkns = session->get_quic_session().get_pkns(space);
                critical_section_guard guard(pkns.get_lock());
                if (pkns.is_modified()) {
                    spaces.insert(space);
                }
                return success;
            };

            lambda_ack(get_session(), protection_initial);
            lambda_ack(get_session(), protection_handshake);
            lambda_ack(get_session(), protection_application);
        }

        if (spaces.empty()) {
            ret = errorcode_t::do_nothing;
        }
    }
    __finally2 {}
    return ret;
}

return_t quic_packet_publisher::prepare_packet_cid(quic_packet* packet, protection_space_t space, tls_direction_t dir) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == packet) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto session = get_session();
        auto& protection = session->get_tls_protection();

        auto ch = get_handshakes().get(tls_hs_client_hello);
        const auto& s_cid = protection.get_secrets().get(tls_context_server_cid);

        if (protection_initial == space) {
            if (from_client == dir) {
                if (ch) {
                    binary_t id;
                    openssl_prng prng;
                    prng.random(id, 8);
                    protection.get_secrets().assign(tls_context_quic_dcid, id);
                    protection.calc(session, tls_hs_client_hello, dir);  // calc initial keys
#if defined DEBUG
                    if (istraceable(trace_category_net)) {
                        basic_stream dbs;
                        dbs.println("QUIC DCID %s", base16_encode(id).c_str());
                        trace_debug_event(trace_category_net, trace_event_quic_packet, &dbs);
                    }
#endif
                }
            } else if (from_server == dir) {
                // tls_context_server_cid
                if (s_cid.empty()) {
                    binary_t id;
                    openssl_prng prng;
                    prng.random(id, 8);
                    protection.get_secrets().assign(tls_context_server_cid, id);
                    session->get_quic_session().get_cid_tracker().insert({0, id});
#if defined DEBUG
                    if (istraceable(trace_category_net)) {
                        basic_stream dbs;
                        dbs.println("QUIC Server CID %s", base16_encode(id).c_str());
                        trace_debug_event(trace_category_net, trace_event_quic_packet, &dbs);
                    }
#endif
                }
            }
        }

        if (from_client == dir) {
            if (ch) {
                const auto& dcid = protection.get_secrets().get(tls_context_quic_dcid);
                packet->set_dcid(dcid);
            } else {
                if (s_cid.empty()) {
                    // do nothing
                } else {
                    packet->set_dcid(s_cid);
                }
            }
        } else if (from_server == dir) {
            switch (space) {
                case protection_initial:
                case protection_handshake: {
                    if (s_cid.empty()) {
                        // do nothing
                    } else {
                        packet->set_scid(s_cid);
                    }
                } break;
                default: {
                    // omit
                } break;
            }
        }
    }
    __finally2 {}
    return ret;
}

return_t quic_packet_publisher::publish_space(protection_space_t space, tls_direction_t dir, uint32 flags, std::list<binary_t>& container) {
    return_t ret = errorcode_t::success;
    __try2 {
        {
            // CRYPTO FRAME
            if (get_handshakes().size()) {
                binary_t temp;
                get_handshakes().for_each([&](tls_handshake* handshake) -> return_t {
                    return_t ret = errorcode_t::success;
                    if (is_kindof_handshake(handshake, space)) {
                        ret = handshake->write(dir, temp);
                    }
                    return ret;
                });
                if (temp.size()) {
                    entry_t entry;
                    entry.how = frame_entry_quic;
                    entry.type = quic_frame_type_crypto;
                    entry.bin = std::move(temp);
                    _segment[space].push_back(std::move(entry));  // segmentation-consume
                }
            }

            if (protection_application == space) {
                for (auto& item : _frame_layout) {
                    entry_t entry;
                    entry.how = item.how;
                    if (frame_entry_quic == item.how) {
                        // do nothing
                    } else if (frame_entry_h3frame == item.how) {
                        // HTTP/3 FRAME
                        entry.type = quic_frame_type_stream;
                        if (item.frame) {
                            binary_t temp;
                            item.frame->write(temp);
                            entry.bin = std::move(temp);
                        }
                        entry.stream_id = item.stream_id;
                        entry.uni_stream_type = item.uni_stream_type;

                        _segment[space].push_back(std::move(entry));  // segmentation-consume
                    } else if (frame_entry_qpack == item.how) {
                        // QPACK ENCODER/DECODER
                        entry.type = quic_frame_type_stream;
                        entry.bin = std::move(item.bin);
                        entry.stream_id = item.stream_id;
                        entry.uni_stream_type = item.uni_stream_type;

                        _segment[space].push_back(std::move(entry));  // segmentation-consume
                    } else {
                        // do nothing
                    }
                }
            }
        }

        binary_t bin;
        if (false == container.empty()) {
            auto iter = container.begin();
            std::advance(iter, container.size() - 1);
            if (get_payload_size() > (*iter).size()) {
                bin = std::move(*iter);
                container.erase(iter);
            }
        }

        auto session = get_session();
        quic_packet_builder builder;
        quic_frame_builder framebuilder;
        while (1) {
            auto packet = builder.set(space).set(session).set(dir).construct().build();
            if (packet) {
                prepare_packet_cid(packet, space, dir);
                auto payload_space = packet->get_max_payload_size() - packet->estimate_overhead() - bin.size();
                packet->get_quic_frames().get_container().set_flags(0);  // turn off distinct_type_in_container

                if (quic_ack_packet & flags) {
                    auto& pkns = session->get_quic_session().get_pkns(space);
                    critical_section_guard guard(pkns.get_lock());
                    if (pkns.is_modified()) {
                        auto frame = (quic_frame_ack*)framebuilder.set(quic_frame_type_ack).set(session).set(packet).build();
                        frame->set_space(space);
                        *packet << frame;
                    }
                }

                if (_segment[space].size()) {
                    size_t size_segments = 0;
                    for (auto& item : _segment[space]) {
                        size_segments += item.bin.size() - item.pos;
                        auto frame = framebuilder.set(item.type).set(session).set(packet).build();
                        if (frame) {
                            if (quic_frame_type_stream == item.type) {
                                auto frame_stream = (quic_frame_stream*)frame;
                                (*frame_stream).set(item.stream_id, item.uni_stream_type);
                            }
                            frame->set(this, packet);
                            if (item.func) {
                                item.func(frame);
                            }
                            *packet << frame;
                        }
                        if (payload_space <= size_segments) {
                            break;
                        }
                    }
                }
                if (protection_application == space) {
                    for (auto& item : _frame_layout) {
                        if (frame_entry_quic == item.how) {
                            auto frame = framebuilder.set(item.type).set(session).set(packet).build();
                            if (frame) {
                                if (quic_frame_type_stream == item.type) {
                                    auto frame_stream = (quic_frame_stream*)frame;
                                    (*frame_stream).set(item.stream_id, item.uni_stream_type);
                                }
                                frame->set(this, packet);
                                if (item.func) {
                                    item.func(frame);
                                }
                                *packet << frame;
                            }
                        }
                    }
                }

                if (flags & quic_pad_packet) {
                    // if max_size is set, fill 0 upto max_size
                    auto frame = (quic_frame_padding*)framebuilder.set(quic_frame_type_padding).set(session).set(packet).build();
                    frame->pad(payload_space, quic_pad_packet);
                    *packet << frame;
                }

                ret = packet->write(dir, bin);

                packet->release();

                container.push_back(std::move(bin));

                if (_segment[space].empty()) {
                    break;
                }
            }
        }
    }
    __finally2 {}
    return ret;
}

return_t quic_packet_publisher::publish(tls_direction_t dir, std::function<void(tls_session*, binary_t&)> func) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        std::set<protection_space_t> spaces;
        ret = probe_spaces(spaces);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        std::list<binary_t> container;
        for (auto space : spaces) {
            uint32 flags = get_flags();
            if (spaces.size() > 1) {
                if (*spaces.rbegin() != space) {
                    flags &= ~quic_pad_packet;
                }
            }

            ret = publish_space(space, dir, flags, container);
            if (errorcode_t::success != ret) {
                break;
            }
        }
        for (auto& item : container) {
            func(get_session(), item);
        }
    }
    __finally2 {}
    return ret;
}

return_t quic_packet_publisher::consume(quic_packet* packet, size_t paid, std::function<return_t(segment_t& segment)> func) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == packet) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto max_payload_size = packet->get_max_payload_size();
        if (paid > max_payload_size) {
            ret = errorcode_t::bad_request;
            __leave2;
        }

        auto payload_space = max_payload_size - paid - packet->estimate_overhead();
        protection_space_t space;

        {
            switch (packet->get_type()) {
                case quic_packet_type_initial: {
                    space = protection_initial;
                } break;
                case quic_packet_type_handshake: {
                    space = protection_handshake;
                } break;
                case quic_packet_type_1_rtt: {
                    space = protection_application;
                } break;
                default: {
                    ret = errorcode_t::bad_request;
                } break;
            }
        }
        if (errorcode_t::success != ret) {
            __leave2;
        }

        {
            critical_section_guard guard(_lock);

            auto& entries = _segment[space];
            if (entries.empty()) {
                ret = errorcode_t::no_data;
                __leave2;
            } else {
                auto iter = entries.begin();
                auto& entry = *iter;
                auto capacity = entry.bin.size() - entry.pos;

                segment_t segment;
                segment.stream = entry.bin.empty() ? nullptr : &entry.bin[0];
                segment.size = entry.bin.size();
                segment.limit = payload_space;
                segment.pos = entry.pos;
                segment.calc(0);

                ret = func(segment);

                entry.pos += segment.len;
                if (entry.bin.size() == entry.pos) {
                    entries.erase(iter);
                }
            }
        }
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
