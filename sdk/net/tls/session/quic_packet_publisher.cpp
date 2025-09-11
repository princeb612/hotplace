/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/stream/basic_stream.hpp>
// #include <sdk/base/stream/segmentation.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/crypto/basic/openssl_prng.hpp>
#include <sdk/net/basic/trial/tls_composer.hpp>
#include <sdk/net/http/http3/http3_frame_builder.hpp>
#include <sdk/net/http/http3/types.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_ack.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_builder.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_crypto.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_http3_stream.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_padding.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_stream.hpp>
#include <sdk/net/tls/quic/frame/quic_frames.hpp>
#include <sdk/net/tls/quic/packet/quic_packet_builder.hpp>
#include <sdk/net/tls/quic_packet_publisher.hpp>
#include <sdk/net/tls/quic_session.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake_builder.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_protection.hpp>
#include <sdk/net/tls/tls_session.hpp>
#include <sdk/net/tls/types.hpp>

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

quic_frames& quic_packet_publisher::get_frames() { return _frames; }

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

quic_packet_publisher& quic_packet_publisher::add_stream(uint64 stream_id, uint8 uni_type, h3_frame_t type, std::function<return_t(http3_frame*)> func) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();

        quic_frame_builder builder;
        auto frame = builder.set(quic_frame_type_stream).set(session).build();
        if (frame) {
            auto h3stream = (quic_frame_http3_stream*)frame;
            h3stream->set(stream_id, uni_type);
            h3stream->get_frames().add(type, session, [&](http3_frame* h3frame) -> return_t {
                return_t ret = errorcode_t::success;
                if (func) {
                    ret = func(h3frame);
                }
                return ret;
            });
            _frames.add(frame);
        }
    }
    __finally2 {}
    return *this;
}

quic_packet_publisher& quic_packet_publisher::add_stream(uint64 stream_id, uint8 uni_type, std::function<return_t(qpack_stream&)> func) {
    __try2 {
        if (nullptr == func) {
            __leave2;
        }

        auto session = get_session();

        quic_frame_builder builder;
        auto frame = builder.set(quic_frame_type_stream).set(session).build();
        if (frame) {
            qpack_stream qp;
            auto& dyntable = session->get_quic_session().get_dynamic_table();
            qp.set_dyntable(&dyntable);
            func(qp);

            (*(quic_frame_http3_stream*)frame).set(stream_id, uni_type).set(std::move(qp.get_binary()));

            _frames.add(frame);
        }
    }
    __finally2 {}
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
            __try2 {
                quic_frame_builder builder;
                auto frame = builder.set(type).set(session).build();
                if (frame) {
                    _frames.add(frame);

                    if (func) {
                        auto test = func(frame);
                        if (errorcode_t::success != test) {
                            frame->release();
                            __leave2;
                        }
                    }

                    _frames.add(frame);
                }
            }
            __finally2 {}
        } break;
    }
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

        if (get_frames().size()) {
            get_frames().for_each([&](quic_frame* frame) -> return_t {
                protection_space_t space;
                kindof_frame(frame, space);
                spaces.insert(space);
                return success;
            });
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

return_t quic_packet_publisher::prepare_frame(protection_space_t space, tls_direction_t dir) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        auto tlsadvisor = tls_advisor::get_instance();

        if (get_handshakes().size()) {
            binary_t bin_crypto;
            get_handshakes().for_each([&](tls_handshake* handshake) -> return_t {
                if (is_kindof_handshake(handshake, space)) {
                    handshake->write(dir, bin_crypto);
                }
                return success;
            });
            // segment->assign(bin_crypto);
        }

        if (get_frames().size()) {
            get_frames().for_each([&](quic_frame* frame) -> return_t {
                if (is_kindof_frame(frame, space)) {
                    binary_t bin_stream;
                    frame->write(dir, bin_stream);
                    // unfragmented.insert({quic_frame_type_stream, std::move(bin_stream)});
                }
                return success;
            });
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
        binary_t bin;
        size_t concat = 0;
        if (false == container.empty()) {
            auto iter = container.begin();
            std::advance(iter, container.size() - 1);
            if (get_payload_size() > (*iter).size()) {
                bin = std::move(*iter);
                concat = bin.size();
                container.erase(iter);
            }
        }

        auto session = get_session();

        quic_packet_builder builder;
        quic_frame_builder framebuilder;
        // segmentation segment(get_payload_size());

        auto packet = builder.set(space).set(session).set(dir).build();
        if (packet) {
            prepare_packet_cid(packet, space, dir);

            if (quic_ack_packet & flags) {
                auto& pkns = session->get_quic_session().get_pkns(space);
                critical_section_guard guard(pkns.get_lock());
                if (pkns.is_modified()) {
                    auto frame = (quic_frame_ack*)framebuilder.set(quic_frame_type_ack).set(session).set(packet).build();
                    frame->set_space(space);
                    *packet << frame;
                }
            }

            if (flags & quic_pad_packet) {
                // if max_size is set, fill 0 upto max_size
                auto frame = (quic_frame_padding*)framebuilder.set(quic_frame_type_padding).set(session).set(packet).build();
                frame->pad(get_payload_size(), quic_pad_packet);
                *packet << frame;
            }

            binary_t bin;
            ret = packet->write(dir, bin);
            container.push_back(std::move(bin));

            packet->release();
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

            // segmentation segment(get_payload_size());

            prepare_frame(space, dir);

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

return_t quic_packet_publisher::kindof_handshake(tls_handshake* handshake, protection_space_t& space) {
    return_t ret = errorcode_t::success;
    __try2 {
        space = protection_default;

        if (nullptr == handshake) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        auto type = handshake->get_type();
        switch (type) {
            case tls_hs_client_hello:
            case tls_hs_server_hello: {
                space = protection_initial;
            } break;
            case tls_hs_encrypted_extensions:
            case tls_hs_certificate:
            case tls_hs_certificate_verify:
            case tls_hs_finished: {
                space = protection_handshake;
            } break;
            case tls_hs_new_session_ticket: {
                space = protection_application;
            } break;
            default: {
                ret = errorcode_t::not_supported;
            } break;
        }
    }
    __finally2 {}
    return ret;
}

bool quic_packet_publisher::is_kindof_handshake(tls_handshake* handshake, protection_space_t space) {
    bool ret = false;
    protection_space_t sp;
    if (success == kindof_handshake(handshake, sp)) {
        ret = (sp == space);
    }
    return ret;
}

return_t quic_packet_publisher::kindof_frame(quic_frame* frame, protection_space_t& space) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == frame) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        space = protection_application;
    }
    __finally2 {}
    return ret;
}

bool quic_packet_publisher::is_kindof_frame(quic_frame* frame, protection_space_t space) {
    bool ret = false;
    protection_space_t sp;
    if (success == kindof_frame(frame, sp)) {
        ret = (sp == space);
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
